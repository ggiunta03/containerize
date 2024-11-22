use nix::sched::{clone, CloneFlags};
use nix::sys::signal::Signal;
use std::process::{Command, Stdio};
use nix::sys::wait::waitpid;
use nix::unistd::getpid;
use nix::mount::{mount, MsFlags};
use nix::unistd::{chdir, chroot};

fn main() {
    println!("Parent PID: {}", getpid());
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
}

fn child_func() -> isize {
    println!("running new shell with PID: {}\n", getpid());
    let new_root = "/my_new_fs";

    // Change to new root
    if let Err(e) = chroot(new_root) {
        eprintln!("Failed to chroot: {}", e);
        return 1;
    }

    if let Err(e) = chdir("/") {
        eprintln!("Failed to chdir: {}", e);
        return 1;
    }

    // Mount proc filesystem
    if let Err(e) = mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    ) {
        eprintln!("Failed to mount proc: {}", e);
        return 1;
    }

    let mut child = Command::new("/bin/bash")
        .arg("-i")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn shell");

    child.wait().expect("Failed to wait for shell");
    0
}
