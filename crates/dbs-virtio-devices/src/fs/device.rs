// Copyright 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::any::Any;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use blobfs::{BlobFs, Config as BlobfsConfig};
use caps::{CapSet, Capability};
use dbs_device::resources::{DeviceResources, ResourceConstraint};
use dbs_utils::epoll_manager::{EpollManager, SubscriberId};
use dbs_utils::rate_limiter::{BucketUpdate, RateLimiter};
use fuse_backend_rs::api::{Vfs, VfsIndex, VfsOptions};
use fuse_backend_rs::passthrough::{CachePolicy, Config as PassthroughConfig, PassthroughFs};
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::VmFd;
use log::{debug, error, info, trace, warn};
use nix::sys::memfd;
use rafs::{
    fs::{Rafs, RafsConfig},
    RafsIoRead,
};
use rlimit::Resource;
use serde::Deserialize;
use virtio_bindings::bindings::virtio_blk::VIRTIO_F_VERSION_1;
use virtio_queue::QueueStateT;
use vm_memory::{
    FileOffset, GuestAddress, GuestAddressSpace, GuestRegionMmap, GuestUsize,
    MmapRegion,
};
use vmm_sys_util::eventfd::EventFd;

use crate::{
    ActivateError, ActivateResult, Error, Result, VirtioDevice, VirtioDeviceConfig,
    VirtioDeviceInfo, VirtioRegionHandler, VirtioSharedMemory, VirtioSharedMemoryList,
    TYPE_VIRTIO_FS,
};

use super::{
    CacheHandler, Error as FsError, Result as FsResult, VirtioFsEpollHandler, VIRTIO_FS_NAME,
};

const CONFIG_SPACE_TAG_SIZE: usize = 36;
const CONFIG_SPACE_NUM_QUEUES_SIZE: usize = 4;
const CONFIG_SPACE_SIZE: usize = CONFIG_SPACE_TAG_SIZE + CONFIG_SPACE_NUM_QUEUES_SIZE;
const NUM_QUEUE_OFFSET: usize = 1;

// Attr and entry timeout values
const CACHE_ALWAYS_TIMEOUT: u64 = 86_400; // 1 day
const CACHE_AUTO_TIMEOUT: u64 = 1;
const CACHE_NONE_TIMEOUT: u64 = 0;

// VirtioFs backend fs type
pub(crate) const PASSTHROUGHFS: &str = "passthroughfs";
pub(crate) const BLOBFS: &str = "blobfs";
pub(crate) const RAFS: &str = "rafs";

#[derive(Clone, Deserialize)]
struct BlobCacheConfig {
    #[serde(default)]
    work_dir: String,
}

/// Info of backend filesystems of VirtioFs
#[allow(dead_code)]
pub struct BackendFsInfo {
    pub(crate) index: VfsIndex,
    pub(crate) fstype: String,
    // (source, config), only suitable for Rafs
    pub(crate) src_cfg: Option<(String, String)>,
}

/// Virtio device for virtiofs
pub struct VirtioFs<AS: GuestAddressSpace> {
    pub(crate) device_info: VirtioDeviceInfo,
    pub(crate) cache_size: u64,
    pub(crate) queue_sizes: Arc<Vec<u16>>,
    pub(crate) thread_pool_size: u16,
    pub(crate) cache_policy: CachePolicy,
    pub(crate) writeback_cache: bool,
    pub(crate) no_open: bool,
    pub(crate) killpriv_v2: bool,
    pub(crate) no_readdir: bool,
    pub(crate) xattr: bool,
    pub(crate) handler: Box<dyn VirtioRegionHandler>,
    pub(crate) fs: Arc<Vfs>,
    pub(crate) backend_fs: HashMap<String, BackendFsInfo>,
    pub(crate) subscriber_id: Option<SubscriberId>,
    pub(crate) id: String,
    pub(crate) rate_limiter: Option<RateLimiter>,
    pub(crate) patch_rate_limiter_fd: EventFd,
    sender: Option<mpsc::Sender<(BucketUpdate, BucketUpdate)>>,
    phantom: PhantomData<AS>,
}

impl<AS> VirtioFs<AS>
where
    AS: GuestAddressSpace + 'static,
{
    pub fn set_patch_rate_limiters(&self, bytes: BucketUpdate, ops: BucketUpdate) -> Result<()> {
        match &self.sender {
            Some(sender) => {
                sender.send((bytes, ops)).map_err(|e| {
                    error!(
                        "{}: failed to send rate-limiter patch data {:?}",
                        VIRTIO_FS_NAME, e
                    );
                    Error::InternalError
                })?;
                self.patch_rate_limiter_fd.write(1).map_err(|e| {
                    error!(
                        "{}: failed to write rate-limiter patch event {:?}",
                        VIRTIO_FS_NAME, e
                    );
                    Error::InternalError
                })?;
                Ok(())
            }
            None => {
                error!(
                    "{}: failed to establish channel to send rate-limiter patch data",
                    VIRTIO_FS_NAME
                );
                Err(Error::InternalError)
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
impl<AS: GuestAddressSpace> VirtioFs<AS> {
    /// Create a new virtiofs device.
    pub fn new(
        tag: &str,
        req_num_queues: usize,
        queue_size: u16,
        cache_size: u64,
        cache_policy: &str,
        thread_pool_size: u16,
        writeback_cache: bool,
        no_open: bool,
        killpriv_v2: bool,
        xattr: bool,
        drop_sys_resource: bool,
        no_readdir: bool,
        handler: Box<dyn VirtioRegionHandler>,
        epoll_mgr: EpollManager,
        rate_limiter: Option<RateLimiter>,
    ) -> Result<Self> {
        info!(
            "{}: tag {} req_num_queues {} queue_size {} cache_size {} cache_policy {} thread_pool_size {} writeback_cache {} no_open {} killpriv_v2 {} xattr {} drop_sys_resource {} no_readdir {}",
            VIRTIO_FS_NAME, tag, req_num_queues, queue_size, cache_size, cache_policy, thread_pool_size, writeback_cache, no_open, killpriv_v2, xattr, drop_sys_resource, no_readdir
        );

        let num_queues = NUM_QUEUE_OFFSET + req_num_queues;

        // Create virtio device config space.
        // First by adding the tag.
        let mut config_space = tag.to_string().into_bytes();
        config_space.resize(CONFIG_SPACE_SIZE, 0);

        // And then by copying the number of queues.
        let mut num_queues_slice: [u8; 4] = (req_num_queues as u32).to_be_bytes();
        num_queues_slice.reverse();
        config_space[CONFIG_SPACE_TAG_SIZE..CONFIG_SPACE_SIZE].copy_from_slice(&num_queues_slice);

        let cache = match CachePolicy::from_str(cache_policy) {
            Ok(c) => c,
            Err(e) => {
                error!(
                    "{}: Parse cache_policy \"{}\" failed: {:?}",
                    VIRTIO_FS_NAME, cache_policy, e
                );
                return Err(Error::InvalidInput);
            }
        };

        // Set rlimit first, in case we dropped CAP_SYS_RESOURCE later and hit EPERM.
        if let Err(e) = set_default_rlimit_nofile() {
            warn!("{}: failed to set rlimit: {:?}", VIRTIO_FS_NAME, e);
        }

        if drop_sys_resource && writeback_cache {
            error!(
                "{}: writeback_cache is not compatible with drop_sys_resource",
                VIRTIO_FS_NAME
            );
            return Err(Error::InvalidInput);
        }

        // Drop CAP_SYS_RESOURCE when creating VirtioFs device, not in activate(), as it's vcpu
        // thread that calls activate(), but we do I/O in vmm epoll thread, so drop cap here.
        if drop_sys_resource {
            info!(
                "{}: Dropping CAP_SYS_RESOURCE, tid {:?}",
                VIRTIO_FS_NAME,
                nix::unistd::gettid()
            );
            if let Err(e) = caps::drop(None, CapSet::Effective, Capability::CAP_SYS_RESOURCE) {
                warn!(
                    "{}: failed to drop CAP_SYS_RESOURCE: {:?}",
                    VIRTIO_FS_NAME, e
                );
            }
        }

        let vfs_opts = VfsOptions {
            no_writeback: !writeback_cache,
            no_open,
            killpriv_v2,
            no_readdir,
            ..VfsOptions::default()
        };

        Ok(VirtioFs {
            device_info: VirtioDeviceInfo::new(
                VIRTIO_FS_NAME.to_string(),
                1u64 << VIRTIO_F_VERSION_1,
                Arc::new(vec![queue_size; num_queues]),
                config_space,
                epoll_mgr,
            ),
            cache_size,
            queue_sizes: Arc::new(vec![queue_size; num_queues]),
            thread_pool_size,
            cache_policy: cache,
            writeback_cache,
            no_open,
            no_readdir,
            killpriv_v2,
            xattr,
            handler,
            fs: Arc::new(Vfs::new(vfs_opts)),
            backend_fs: HashMap::new(),
            subscriber_id: None,
            id: tag.to_string(),
            rate_limiter,
            patch_rate_limiter_fd: EventFd::new(0).unwrap(),
            sender: None,
            phantom: PhantomData,
        })
    }

    fn is_dax_on(&self) -> bool {
        self.cache_size > 0
    }

    fn get_timeout(&self) -> Duration {
        match self.cache_policy {
            CachePolicy::Always => Duration::from_secs(CACHE_ALWAYS_TIMEOUT),
            CachePolicy::Never => Duration::from_secs(CACHE_NONE_TIMEOUT),
            CachePolicy::Auto => Duration::from_secs(CACHE_AUTO_TIMEOUT),
        }
    }

    fn parse_blobfs_cfg(
        &self,
        source: &str,
        config: Option<String>,
        dax_threshold_size_kb: Option<u64>,
    ) -> FsResult<(String, String, Option<u64>)> {
        let (blob_cache_dir, blob_ondemand_cfg) = match config.as_ref() {
            Some(cfg) => {
                let conf = RafsConfig::from_str(cfg).map_err(|e| {
                    error!("failed to load rafs config {} error: {:?}", &cfg, e);
                    FsError::InvalidData
                })?;

                // v6 doesn't support digest validation yet.
                if conf.digest_validate {
                    error!("config.digest_validate needs to be false");
                    return Err(FsError::InvalidData);
                }

                let cache_config = conf.device.cache.cache_config;
                let blob_config: BlobCacheConfig =
                    serde_json::from_value(cache_config).map_err(|e| {
                        error!("failed to get blob config");
                        FsError::BackendFs(e.to_string())
                    })?;

                let blob_ondemand_cfg = format!(
                    r#"
                    {{
                        "rafs_conf": {},
                        "bootstrap_path": "{}",
                        "blob_cache_dir": "{}"
                    }}"#,
                    cfg, source, &blob_config.work_dir
                );

                (blob_config.work_dir, blob_ondemand_cfg)
            }
            None => return Err(FsError::BackendFs("no rafs config file".to_string())),
        };

        let dax_file_size = match dax_threshold_size_kb {
            Some(size) => Some(kb_to_bytes(size)?),
            None => None,
        };

        Ok((blob_cache_dir, blob_ondemand_cfg, dax_file_size))
    }

    pub fn manipulate_backend_fs(
        &mut self,
        source: Option<String>,
        fstype: Option<String>,
        mountpoint: &str,
        config: Option<String>,
        ops: &str,
        prefetch_list_path: Option<String>,
        dax_threshold_size_kb: Option<u64>,
    ) -> FsResult<()> {
        debug!(
            "source {:?}, fstype {:?}, mountpoint {:?}, config {:?}, ops {:?}, prefetch_list_path {:?}, dax_threshold_size_kb 0x{:x?}",
            source, fstype, mountpoint, config, ops, prefetch_list_path, dax_threshold_size_kb
        );
        match ops {
            "mount" => {
                if source.is_none() {
                    error!("{}: source is required for mount.", VIRTIO_FS_NAME);
                    return Err(FsError::InvalidData);
                }
                // safe because is not None
                let source = source.unwrap();
                match fstype.as_deref() {
                    Some("Blobfs") | Some(BLOBFS) => {
                        self.mount_blobfs(source, mountpoint, config, dax_threshold_size_kb)
                    }
                    Some("PassthroughFs") | Some(PASSTHROUGHFS) => {
                        self.mount_passthroughfs(source, mountpoint, dax_threshold_size_kb)
                    }
                    Some("Rafs") | Some(RAFS) => {
                        self.mount_rafs(source, mountpoint, config, prefetch_list_path)
                    }
                    _ => {
                        error!("http_server: type is not invalid.");
                        Err(FsError::InvalidData)
                    }
                }
            }
            "umount" => {
                self.fs.umount(mountpoint).map_err(|e| {
                    error!("umount {:?}", e);
                    FsError::InvalidData
                })?;
                self.backend_fs.remove(mountpoint);
                Ok(())
            }
            "update" => {
                info!("switch backend");
                self.update_rafs(source, mountpoint, config)
            }
            _ => {
                error!("invalid ops, mount failed.");
                Err(FsError::InvalidData)
            }
        }
    }

    fn mount_blobfs(
        &mut self,
        source: String,
        mountpoint: &str,
        config: Option<String>,
        dax_threshold_size_kb: Option<u64>,
    ) -> FsResult<()> {
        debug!("http_server blobfs");
        let timeout = self.get_timeout();
        let (blob_cache_dir, blob_ondemand_cfg, dax_file_size) =
            self.parse_blobfs_cfg(&source, config, dax_threshold_size_kb)?;

        let fs_cfg = BlobfsConfig {
            ps_config: PassthroughConfig {
                root_dir: blob_cache_dir,
                do_import: true,
                writeback: self.writeback_cache,
                no_open: self.no_open,
                xattr: self.xattr,
                cache_policy: self.cache_policy.clone(),
                entry_timeout: timeout,
                attr_timeout: timeout,
                dax_file_size,
                ..Default::default()
            },
            blob_ondemand_cfg,
        };
        let blob_fs = BlobFs::new(fs_cfg).map_err(FsError::IOError)?;
        blob_fs.import().map_err(FsError::IOError)?;
        debug!("blobfs mounted");

        let fs = Box::new(blob_fs);
        match self.fs.mount(fs, mountpoint) {
            Ok(idx) => {
                self.backend_fs.insert(
                    mountpoint.to_string(),
                    BackendFsInfo {
                        index: idx,
                        fstype: BLOBFS.to_string(),
                        src_cfg: None,
                    },
                );
                Ok(())
            }
            Err(e) => {
                error!("blobfs mount {:?}", e);
                Err(FsError::InvalidData)
            }
        }
    }

    fn mount_passthroughfs(
        &mut self,
        source: String,
        mountpoint: &str,
        dax_threshold_size_kb: Option<u64>,
    ) -> FsResult<()> {
        debug!("http_server passthrough");
        let timeout = self.get_timeout();

        let dax_threshold_size = match dax_threshold_size_kb {
            Some(size) => Some(kb_to_bytes(size)?),
            None => None,
        };

        let fs_cfg = PassthroughConfig {
            root_dir: source,
            do_import: false,
            writeback: self.writeback_cache,
            no_open: self.no_open,
            no_readdir: self.no_readdir,
            killpriv_v2: self.killpriv_v2,
            xattr: self.xattr,
            cache_policy: self.cache_policy.clone(),
            entry_timeout: timeout,
            attr_timeout: timeout,
            dax_file_size: dax_threshold_size,
            ..Default::default()
        };

        let passthrough_fs = PassthroughFs::new(fs_cfg).map_err(FsError::IOError)?;
        passthrough_fs.import().map_err(FsError::IOError)?;
        debug!("passthroughfs mounted");

        let fs = Box::new(passthrough_fs);
        match self.fs.mount(fs, mountpoint) {
            Ok(idx) => {
                self.backend_fs.insert(
                    mountpoint.to_string(),
                    BackendFsInfo {
                        index: idx,
                        fstype: PASSTHROUGHFS.to_string(),
                        src_cfg: None,
                    },
                );
                Ok(())
            }
            Err(e) => {
                error!("passthroughfs mount {:?}", e);
                Err(FsError::InvalidData)
            }
        }
    }

    fn mount_rafs(
        &mut self,
        source: String,
        mountpoint: &str,
        config: Option<String>,
        prefetch_list_path: Option<String>,
    ) -> FsResult<()> {
        debug!("http_server rafs");
        let mut file = <dyn RafsIoRead>::from_file(&source)
            .map_err(|e| FsError::BackendFs(format!("RafsIoRead failed: {:?}", e)))?;
        let (mut rafs, rafs_cfg) = match config.as_ref() {
            Some(cfg) => {
                let rafs_conf: RafsConfig =
                    serde_json::from_str(cfg).map_err(|e| FsError::BackendFs(e.to_string()))?;

                (
                    Rafs::new(rafs_conf, mountpoint, &mut file)
                        .map_err(|e| FsError::BackendFs(format!("Rafs::new() failed: {:?}", e)))?,
                    cfg.clone(),
                )
            }
            None => return Err(FsError::BackendFs("no rafs config file".to_string())),
        };
        let prefetch_files = parse_prefetch_files(prefetch_list_path.clone());
        debug!(
            "{}: Import rafs with prefetch_files {:?}",
            VIRTIO_FS_NAME, prefetch_files
        );
        rafs.import(file, prefetch_files)
            .map_err(|e| FsError::BackendFs(format!("Import rafs failed: {:?}", e)))?;
        info!(
            "{}: Rafs imported with prefetch_list_path {:?}",
            VIRTIO_FS_NAME, prefetch_list_path
        );
        let fs = Box::new(rafs);
        match self.fs.mount(fs, mountpoint) {
            Ok(idx) => {
                self.backend_fs.insert(
                    mountpoint.to_string(),
                    BackendFsInfo {
                        index: idx,
                        fstype: RAFS.to_string(),
                        src_cfg: Some((source, rafs_cfg)),
                    },
                );
                Ok(())
            }
            Err(e) => {
                error!("Rafs mount failed: {:?}", e);
                Err(FsError::InvalidData)
            }
        }
    }

    fn update_rafs(
        &mut self,
        source: Option<String>,
        mountpoint: &str,
        config: Option<String>,
    ) -> FsResult<()> {
        if config.is_none() {
            return Err(FsError::BackendFs("no rafs config file".to_string()));
        }
        if source.is_none() {
            return Err(FsError::BackendFs(format!(
                "rafs mounted at {} doesn't have source configured",
                mountpoint
            )));
        }
        // safe because config is not None.
        let config = config.unwrap();
        let source = source.unwrap();
        let rafs_conf: RafsConfig =
            serde_json::from_str(&config).map_err(|e| FsError::BackendFs(e.to_string()))?;
        // Update rafs config, update BackendFsInfo as well.
        let new_info = match self.backend_fs.get(mountpoint) {
            Some(orig_info) => BackendFsInfo {
                index: orig_info.index,
                fstype: orig_info.fstype.clone(),
                src_cfg: Some((source.to_string(), config)),
            },
            None => {
                return Err(FsError::BackendFs(format!(
                    "rafs mount point {} is not mounted",
                    mountpoint
                )));
            }
        };
        let rootfs = match self.fs.get_rootfs(mountpoint) {
            Ok(fs) => match fs {
                Some(f) => f,
                None => {
                    return Err(FsError::BackendFs(format!(
                        "rafs get_rootfs() failed: mountpoint {} not mounted",
                        mountpoint
                    )));
                }
            },
            Err(e) => {
                return Err(FsError::BackendFs(format!(
                    "rafs get_rootfs() failed: {:?}",
                    e
                )));
            }
        };
        let any_fs = rootfs.deref().as_any();
        if let Some(fs_swap) = any_fs.downcast_ref::<Rafs>() {
            let mut file = <dyn RafsIoRead>::from_file(&source)
                .map_err(|e| FsError::BackendFs(format!("RafsIoRead failed: {:?}", e)))?;

            fs_swap
                .update(&mut file, rafs_conf)
                .map_err(|e| FsError::BackendFs(format!("Update rafs failed: {:?}", e)))?;
            self.backend_fs.insert(mountpoint.to_string(), new_info);
            Ok(())
        } else {
            Err(FsError::BackendFs("no rafs is found".to_string()))
        }
    }

    fn register_mmap_region(
        &mut self,
        vm_fd: Arc<VmFd>,
        guest_addr: u64,
        len: u64,
        slot_res: &[u32],
    ) -> Result<Arc<GuestRegionMmap>> {
        // Create file backend for virtiofs's mmap region to let goku and
        // vhost-user slave can remap memory by memfd. However, this is not a
        // complete solution, because when dax is actually on, they need to be
        // notified of the change in the dax memory mapping relationship.
        let file_offset = {
            let fd = memfd::memfd_create(
                // safe to unwrap, no nul byte in file name
                &CString::new("virtio_fs_mem").unwrap(),
                memfd::MemFdCreateFlag::empty(),
            )
            .map_err(|e| Error::VirtioFs(FsError::MemFdCreate(e)))?;
            let file: File = unsafe { File::from_raw_fd(fd) };
            file.set_len(len)
                .map_err(|e| Error::VirtioFs(FsError::SetFileSize(e)))?;
            Some(FileOffset::new(file, 0))
        };

        // unmap will be handled on MmapRegion'd Drop.
        let mmap_region = MmapRegion::build(
            file_offset,
            len as usize,
            libc::PROT_NONE,
            libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_PRIVATE,
        )
        .map_err(Error::NewMmapRegion)?;

        let host_addr: u64 = mmap_region.as_ptr() as u64;
        let kvm_mem_region = kvm_userspace_memory_region {
            slot: slot_res[0],
            flags: 0,
            guest_phys_addr: guest_addr,
            memory_size: len,
            userspace_addr: host_addr,
        };
        debug!(
            "{}: mmio shared memory kvm_region: {:?}",
            self.id, kvm_mem_region,
        );

        // Safe because the user mem region is just created, and kvm slot is allocated
        // by resource allocator.
        unsafe {
            vm_fd
                .set_user_memory_region(kvm_mem_region)
                .map_err(Error::SetUserMemoryRegion)?
        };

        let region = Arc::new(
            GuestRegionMmap::new(mmap_region, GuestAddress(guest_addr))
                .map_err(Error::InsertMmap)?,
        );
        self.handler.insert_region(region.clone())?;

        Ok(region)
    }
}

fn parse_prefetch_files(prefetch_list_path: Option<String>) -> Option<Vec<PathBuf>> {
    let prefetch_files: Option<Vec<PathBuf>> = match prefetch_list_path {
        Some(p) => {
            match File::open(p.as_str()) {
                Ok(f) => {
                    let r = BufReader::new(f);
                    // All prefetch files should be absolute path
                    let v: Vec<PathBuf> = r
                        .lines()
                        .filter(|l| {
                            let lref = l.as_ref();
                            lref.is_ok() && lref.unwrap().starts_with('/')
                        })
                        .map(|l| PathBuf::from(l.unwrap().as_str()))
                        .collect();
                    if v.is_empty() {
                        None
                    } else {
                        Some(v)
                    }
                }
                Err(e) => {
                    // We could contineu without prefetch files, just print warning and return
                    warn!(
                        "{}: Open prefetch_file_path {} failed: {:?}",
                        VIRTIO_FS_NAME,
                        p.as_str(),
                        e
                    );
                    None
                }
            }
        }
        None => None,
    };
    prefetch_files
}

fn kb_to_bytes(kb: u64) -> FsResult<u64> {
    if (kb & 0xffc0_0000_0000_0000) != 0 {
        error!(
            "dax_threshold_size_kb * 1024 overflow. dax_threshold_size_kb is 0x{:x}.",
            kb
        );
        return Err(FsError::InvalidData);
    }

    let bytes = kb << 10;
    Ok(bytes)
}

fn set_default_rlimit_nofile() -> Result<()> {
    // Our default RLIMIT_NOFILE target.
    let mut max_fds: u64 = 300_000;
    // leave at least this many fds free
    let reserved_fds: u64 = 16_384;

    // Reduce max_fds below the system-wide maximum, if necessary.
    // This ensures there are fds available for other processes so we
    // don't cause resource exhaustion.
    let mut file_max = String::new();
    let mut f = File::open("/proc/sys/fs/file-max").map_err(|e| {
        error!(
            "{}: failed to read /proc/sys/fs/file-max {:?}",
            VIRTIO_FS_NAME, e
        );
        Error::IOError(e)
    })?;
    f.read_to_string(&mut file_max)?;
    let file_max = file_max.trim().parse::<u64>().map_err(|e| {
        error!("{}: read fs.file-max sysctl wrong {:?}", VIRTIO_FS_NAME, e);
        Error::InvalidInput
    })?;
    if file_max < 2 * reserved_fds {
        error!(
            "{}: The fs.file-max sysctl ({}) is too low to allow a reasonable number of open files ({}).",
            VIRTIO_FS_NAME, file_max, 2 * reserved_fds
        );
        return Err(Error::InvalidInput);
    }

    max_fds = std::cmp::min(file_max - reserved_fds, max_fds);
    let rlimit_nofile = Resource::NOFILE
        .get()
        .map(|(curr, _)| if curr >= max_fds { 0 } else { max_fds })
        .map_err(|e| {
            error!("{}: failed to get rlimit {:?}", VIRTIO_FS_NAME, e);
            Error::IOError(e)
        })?;

    if rlimit_nofile == 0 {
        info!(
            "{}: original rlimit nofile is greater than max_fds({}), keep rlimit nofile setting",
            VIRTIO_FS_NAME, max_fds
        );
        Ok(())
    } else {
        info!(
            "{}: set rlimit {} (max_fds {})",
            VIRTIO_FS_NAME, rlimit_nofile, max_fds
        );

        Resource::NOFILE
            .set(rlimit_nofile, rlimit_nofile)
            .map_err(|e| {
                error!("{}: failed to set rlimit {:?}", VIRTIO_FS_NAME, e);
                Error::IOError(e)
            })
    }
}

impl<AS, Q> VirtioDevice<AS, Q, GuestRegionMmap> for VirtioFs<AS>
where
    AS: 'static + GuestAddressSpace + Clone + Send + Sync,
    AS::T: Send,
    AS::M: Sync + Send,
    Q: QueueStateT + Send + 'static,
{
    fn device_type(&self) -> u32 {
        TYPE_VIRTIO_FS
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn get_avail_features(&self, page: u32) -> u32 {
        self.device_info.get_avail_features(page)
    }

    fn set_acked_features(&mut self, page: u32, value: u32) {
        trace!(
            target: VIRTIO_FS_NAME,
            "{}: VirtioDevice::set_acked_features({}, 0x{:x})",
            self.id,
            page,
            value
        );
        self.device_info.set_acked_features(page, value)
    }

    fn read_config(&mut self, offset: u64, data: &mut [u8]) {
        trace!(
            target: VIRTIO_FS_NAME,
            "{}: VirtioDevice::read_config(0x{:x}, {:?})",
            self.id,
            offset,
            data
        );
        self.device_info.read_config(offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        trace!(
            target: VIRTIO_FS_NAME,
            "{}: VirtioDevice::write_config(0x{:x}, {:?})",
            self.id,
            offset,
            data
        );
        self.device_info.write_config(offset, data)
    }

    fn activate(&mut self, config: VirtioDeviceConfig<AS, Q>) -> ActivateResult {
        trace!(
            target: VIRTIO_FS_NAME,
            "{}: VirtioDevice::activate()",
            self.id
        );

        self.device_info.check_queue_sizes(&config.queues)?;

        let (sender, receiver) = mpsc::channel();
        self.sender = Some(sender);
        let rate_limiter = self.rate_limiter.take().unwrap_or_default();
        let patch_rate_limiter_fd = self.patch_rate_limiter_fd.try_clone().map_err(|e| {
            error!(
                "{}: failed to clone patch rate limiter eventfd {:?}",
                VIRTIO_FS_NAME, e
            );
            ActivateError::InternalError
        })?;

        let cache_handler = if let Some((addr, _guest_addr)) = config.get_shm_region_addr() {
            let handler = CacheHandler {
                cache_size: self.cache_size,
                mmap_cache_addr: addr,
                id: self.id.clone(),
            };

            Some(handler)
        } else {
            None
        };

        let handler = VirtioFsEpollHandler::new(
            config,
            self.fs.clone(),
            cache_handler,
            self.thread_pool_size,
            self.id.clone(),
            rate_limiter,
            patch_rate_limiter_fd,
            Some(receiver),
        );

        self.subscriber_id = Some(self.device_info.register_event_handler(Box::new(handler)));

        Ok(())
    }

    // Please keep in synchronization with vhost/fs.rs
    fn get_resource_requirements(
        &self,
        requests: &mut Vec<ResourceConstraint>,
        use_generic_irq: bool,
    ) {
        trace!(
            target: VIRTIO_FS_NAME,
            "{}: VirtioDevice::get_resource_requirements()",
            self.id
        );
        requests.push(ResourceConstraint::LegacyIrq { irq: None });
        if use_generic_irq {
            // Allocate one irq for device configuration change events, and one irq for each queue.
            requests.push(ResourceConstraint::GenericIrq {
                size: (self.queue_sizes.len() + 1) as u32,
            });
        }

        // Check if we have dax enabled or not, just return if no dax window requested.
        if !self.is_dax_on() {
            info!("{}: DAX window is disabled.", self.id);
            return;
        }

        // Request for DAX window. The memory needs to be 2MiB aligned in order to support
        // hugepages, and needs to be above 4G to avoid confliction with lapic/ioapic devices.
        requests.push(ResourceConstraint::MmioAddress {
            range: Some((0x1_0000_0000, std::u64::MAX)),
            align: 0x0020_0000,
            size: self.cache_size,
        });

        // Request for new kvm memory slot for DAX window.
        requests.push(ResourceConstraint::KvmMemSlot {
            slot: None,
            size: 1,
        });
    }

    // Please keep in synchronization with vhost/fs.rs
    fn set_resource(
        &mut self,
        vm_fd: Arc<VmFd>,
        resource: DeviceResources,
    ) -> Result<Option<VirtioSharedMemoryList<GuestRegionMmap>>> {
        trace!(
            target: VIRTIO_FS_NAME,
            "{}: VirtioDevice::set_resource()",
            self.id
        );

        let mmio_res = resource.get_mmio_address_ranges();
        let slot_res = resource.get_kvm_mem_slots();

        // Do nothing if there's no dax window requested.
        if mmio_res.is_empty() {
            return Ok(None);
        }

        // Make sure we have the correct resource as requested, and currently we only support one
        // shm region for DAX window (version table and journal are not supported yet).
        if mmio_res.len() != slot_res.len() || mmio_res.len() != 1 {
            error!(
                "{}: wrong number of mmio or kvm slot resource ({}, {})",
                self.id,
                mmio_res.len(),
                slot_res.len()
            );
            return Err(Error::InvalidResource);
        }

        let guest_addr = mmio_res[0].0;
        let cache_len = mmio_res[0].1;

        let mmap_region = self.register_mmap_region(vm_fd, guest_addr, cache_len, &slot_res)?;

        Ok(Some(VirtioSharedMemoryList {
            host_addr: mmap_region.deref().deref().as_ptr() as u64,
            guest_addr: GuestAddress(guest_addr),
            len: cache_len as GuestUsize,
            kvm_userspace_memory_region_flags: 0,
            kvm_userspace_memory_region_slot: slot_res[0],
            region_list: vec![VirtioSharedMemory {
                offset: 0,
                len: cache_len,
            }],
            mmap_region,
        }))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
