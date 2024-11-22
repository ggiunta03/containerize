use cgroups_rs::{
    cgroup_builder::*, cpu::CpuController, memory::MemController, Cgroup,
};
use nix::mount::{mount, umount, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::signal::Signal;
use nix::sys::wait::waitpid;
use nix::unistd::getpid;
use nix::unistd::{chdir, chroot};
use std::process::{Command, Stdio};
use std::path::Path;

fn main() {
    println!("Parent PID: {}", getpid());
    let proc_path = Path::new("/tmp/test_fs/proc");
    let sys_path = Path::new("/tmp/test_fs/sys");
    let cgroup_path = Path::new("/tmp/test_fs/sys/fs/cgroup");
    let stack = &mut [0; (4 * 1024 * 1024)];
    let flags = CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWIPC;

    let child_pid = unsafe {
        clone(
            Box::new(|| child_func()),
            stack,
            flags,
            Some(Signal::SIGCHLD as i32),
        )
    }
    .expect("Failed to clone");

    println!("Parent process waiting for child");
    waitpid(child_pid, None).expect("Failed to wait for child");
    println!("Child process finished");

    if proc_path.exists() {
        let _ = umount(proc_path);
    }

    if sys_path.exists() {
        let _ = umount(cgroup_path);
    }

    if sys_path.exists() {
        let _ = umount(sys_path);
    }
}

/// Create new hierarchy and cgroup. This way the cgroup isn't conflicting with the current hierarchy
/// Set memory and cpu limits based on parameters
///
/// Return valid cgroup
fn setup_groups(
    name: &str,
    mem_limit_bytes: i64,
    cpu_quota: i64,
    cpu_period: u64,
) -> Result<Cgroup, Box<dyn std::error::Error>> {
    // Create unique hierarchy to build new cgroup under
    let hierarchy = cgroups_rs::hierarchies::auto();
    let cgroup: Cgroup = CgroupBuilder::new(name).build(hierarchy)?;

    let memory_controller = cgroup.controller_of::<MemController>().ok_or("Failed to get memory controller")?;
    memory_controller.set_limit(mem_limit_bytes)?;

    let cpu_controller = cgroup.controller_of::<CpuController>().ok_or("Failed to get cpu controller")?;
    cpu_controller.set_cfs_quota(cpu_quota)?;
    cpu_controller.set_cfs_period(cpu_period)?;

    Ok(cgroup)
}

fn setup_mounts(new_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let sys_path = new_root.join("sys");
    let proc_path = new_root.join("proc");
    std::fs::create_dir_all(&sys_path)?;
    std::fs::create_dir_all(&proc_path)?;

    // First mount the main sysfs
    mount(
        Some("sysfs"),
        &sys_path,
        Some("sysfs"),
        MsFlags::empty(),
        None::<&str>
    )?;

    // Create and mount important sysfs subdirectories
    let sys_fs_cgroup = sys_path.join("fs/cgroup");
    std::fs::create_dir_all(&sys_fs_cgroup)?;

    // Mount cgroup2 filesystem
    mount(
        Some("cgroup2"),
        &sys_fs_cgroup,
        Some("cgroup2"),
        MsFlags::empty(),
        None::<&str>
    )?;

    // Mount procfs
    println!("Mounting procfs...");
    mount(
        Some("proc"),
        &proc_path,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>
    )?;

    Ok(())
}

/// Mount important filesystems like /proc and /sys
/// Change root and place yourself in /
fn enter_chroot(new_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = setup_mounts(new_root) {
        eprintln!("Failed to setup mounts: {}", e);
        return Ok(());
    }

    // Change to new root
    if let Err(e) = chroot(new_root) {
        eprintln!("Failed to chroot: {}", e);
        return Err(Box::new(e));
    }

    if let Err(e) = chdir("/") {
        eprintln!("Failed to chdir: {}", e);
        return Err(Box::new(e));
    }
    Ok(())
}

/// This is the child routine passed to Clone::()
/// After setting up our environment and changing our root
/// we start up an interactive bash shell. Finally, we can add our shells pid to
/// our newly created cgroup to make use of those resource restrictions we set above.
fn child_func() -> isize {
    println!("running new shell with PID: {}\n", getpid());
    let new_root = Path::new("/tmp/test_fs");

    if let Err(e) = enter_chroot(&new_root) {
        eprintln!("Failed to setup chroot shit: {}", e);
        return 1;
    }
    let cgroup = match setup_groups("my_container", 1024*1024*4, 50000, 100000) {
        Err(e) => {
            eprintln!("Failed to setup some group: {}", e);
            return 1;
        },
        Ok(group) => group,
    };

    let mut child = Command::new("/bin/bash")
        .arg("-i")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn shell");

    let pid = cgroups_rs::CgroupPid::from(child.id() as u64);
    let _ = cgroup.add_task_by_tgid(pid);

    child.wait().expect("Failed to wait for shell");
    0
}
