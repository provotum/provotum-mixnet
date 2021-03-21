mod cli;
mod voting;

use async_std::task;
use clap::Clap;
use cli::cli::{Opts, SealerSubCommand, SubCommand, VASubCommand};
use voting::va::{change_vote_phase, setup_vote};
use voting::voter::create_votes;

fn main() {
    let opts: Opts = Opts::parse();

    // You can handle information about subcommands by requesting their matches by name
    // (as below), requesting just the name used, or both at the same time
    match opts.subcmd {
        SubCommand::Voter(t) => {
            println!("Voter. Creating votes... {:?}", t);
            task::block_on(async {
                let result =
                    task::spawn(create_votes(t.vote, t.question, t.nr_of_votes, t.votes)).await;
                match result {
                    Ok(_) => println!("successfully created {:?} votes.", t.nr_of_votes),
                    Err(err) => println!("failed to create vote: {:?}", err),
                }
            });
        }
        SubCommand::VotingAuthority(t) => match t.subcmd {
            VASubCommand::SetupVote(t) => {
                println!("VA. Creating vote... {:?}", t);
                task::block_on(async {
                    let result = task::spawn(setup_vote(t.vote, t.question)).await;
                    match result {
                        Ok(_) => println!("successfully created vote!"),
                        Err(err) => println!("failed to create vote: {:?}", err),
                    }
                });
            }
            VASubCommand::StoreQuestion(t) => {
                println!("VA. Store Question... {:?}", t);
            }
            VASubCommand::SetVotePhase(t) => {
                println!("VA. Changing Vote Phase... {:?}", t);
                task::block_on(async {
                    let result = task::spawn(change_vote_phase(t.vote, t.phase)).await;
                    match result {
                        Ok(_) => println!("successfully update vote phase!"),
                        Err(err) => println!("failed to set vote: {:?}", err),
                    }
                });
            }
        },
        SubCommand::Sealer(t) => match t.subcmd {
            SealerSubCommand::KeyGeneration(t) => {
                println!("Printing sealer - key generation... {:?}", t);
            }
            SealerSubCommand::PartialDecryption(t) => {
                println!("Printing sealer - partial decryption... {:?}", t);
            }
        },
    }
}
