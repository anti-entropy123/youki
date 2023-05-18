/// UnifiedSyscallError aims to simplify error handling of syscalls in
/// libcontainer. In many occasions, we mix nix::Error, std::io::Error and our
/// own syscall wrappers, which makes error handling complicated.
#[derive(Debug, thiserror::Error)]
pub enum UnifiedSyscallError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    Syscall(#[from] crate::syscall::SyscallError),
}

#[derive(Debug, thiserror::Error)]
pub enum MissingSpecError {
    #[error("missing process in spec")]
    Process,
    #[error("missing linux in spec")]
    Linux,
    #[error("missing args in the process spec")]
    Args,
    #[error("missing root in the spec")]
    Root,
}

#[derive(Debug, thiserror::Error)]
pub enum LibcontainerError {
    #[error("failed to perform operation due to incorrect container status")]
    IncorrectContainerStatus,
    #[error("container already exists")]
    ContainerAlreadyExists,
    #[error("invalid input")]
    InvalidInput(String),
    #[error("requires at least one executors")]
    NoExecutors,

    // Invalid inputs
    #[error(transparent)]
    InvalidID(#[from] ErrInvalidID),
    #[error(transparent)]
    MissingSpec(#[from] MissingSpecError),
    #[error("invalid runtime spec")]
    InvalidSpec(#[from] ErrInvalidSpec),

    // Errors from submodules and other errors
    #[error(transparent)]
    Tty(#[from] crate::tty::TTYError),
    #[error(transparent)]
    Rootless(#[from] crate::rootless::RootlessError),
    #[error(transparent)]
    NotifyListener(#[from] crate::notify_socket::NotifyListenerError),
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Hook(#[from] crate::hooks::HookError),
    #[error(transparent)]
    State(#[from] crate::container::state::StateError),
    #[error("oci spec error")]
    Spec(#[from] oci_spec::OciSpecError),
    #[error("cgroups error: {0}")]
    Cgroups(String),
    #[error(transparent)]
    MainProcess(#[from] crate::process::container_main_process::ProcessError),
    #[error(transparent)]
    Procfs(#[from] procfs::ProcError),

    // Catch all errors that are not covered by the above
    #[error("syscall error")]
    OtherSyscall(#[source] nix::Error),
    #[error("IO error")]
    OtherIO(#[source] std::io::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ErrInvalidID {
    #[error("container id can't be empty")]
    Empty,
    #[error("container id contains invalid characters: {0}")]
    InvalidChars(char),
    #[error("container id can't be used to represent a file name (such as . or ..)")]
    FileName,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrInvalidSpec {
    #[error("runtime spec has incompatible version. Only 1.X.Y is supported")]
    UnsupportedVersion,
    #[error("apparmor is specified but not enabled on this system")]
    AppArmorNotEnabled,
}