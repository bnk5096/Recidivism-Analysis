import sys
from git import Repo

def git_reset(repos_file: str, repos_location: str):
    """Reset the repositories from a failed run.

    Args:
        repos_file (str): file with the repo list in it
        repos_location (str): directory with the repos in it
    """
    with open(repos_file) as repos:
        for repo in repos:
            print("Working on " + repo.strip() + "...")
            repo_obj = Repo(repos_location + "/" + repo.strip())
            git_cmd = repo_obj.git
            try:
                git_cmd.checkout("master")
                print("Checked out master.")
            except:
                try:
                    git_cmd.checkout("main")
                    print("Checked out main.")
                except:
                    try:
                        git_cmd.checkout("dev")
                        print("Checked out dev.")
                    except:
                        print("None of the default checkouts seem to have worked.")
                        continue
            print("Pulling...")
            try:
                git_cmd.pull()
            except:
                print("Repo " + repo.strip() + " will need help to pull.")
            print("Finished " + repo.strip() + ".")

def main():
    repos_file = sys.argv[1]
    repos_location = sys.argv[2]
    git_reset(repos_file, repos_location)

if __name__ == "__main__":
    main()