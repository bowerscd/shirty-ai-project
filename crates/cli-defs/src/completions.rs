//! Shared `completions <shell>` subcommand args. Used by both `yggdrasil`
//! and `yggdrasilctl` so operators get a uniform install one-liner
//! (`yggdrasilctl completions bash | sudo tee /etc/bash_completion.d/yggdrasilctl`).

use clap::Args;
use clap_complete::Shell;

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Target shell. The completion script is printed to stdout.
    #[arg(value_enum)]
    pub shell: Shell,
}
