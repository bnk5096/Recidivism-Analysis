from git import Repo
from datetime import datetime, timedelta, timezone
import sys

def collect_commits(local_repo: str, out_file: str):
    """ Collects the 30-day snapshots and saves them to a csv file.

    Args:
        local_repo (str): repository location
        out_file (str): location to save csv to
    """
    collected_commits = []
    # get the repo as an object and the commit list in reverse order
    repo = Repo(local_repo)
    commit_iterator = repo.iter_commits(reverse=True, date_order=True)
    initial_commit = next(commit_iterator)
    initial_date = initial_commit.committed_datetime
    collected_commits.append((str(initial_date), str(initial_commit.hexsha)))
    # move ahead 30 days, reset time information, synchronize time zone
    next_target_date = initial_date + timedelta(days=30)
    next_target_stripped = datetime(next_target_date.year, next_target_date.month, next_target_date.day, tzinfo=next_target_date.tzinfo)
    current_commit = next(commit_iterator)
    # while the next time is before today
    while next_target_stripped < datetime.now(timezone(initial_date.utcoffset())):
        # search for a commit that is after the target date
        while current_commit.committed_datetime < next_target_stripped:
            current_commit = next(commit_iterator, None)
            # if there are no more commits, stop
            if current_commit == None:
                break
        if current_commit == None:
            break
        current_commit_date = current_commit.committed_datetime
        collected_commits.append((str(current_commit_date), str(current_commit.hexsha)))
        # move ahead 30 days, again resetting time and synchronizing time zone
        next_target_date = current_commit_date + timedelta(days=30)
        next_target_stripped = datetime(next_target_date.year, next_target_date.month, next_target_date.day, tzinfo=next_target_date.tzinfo)
    # save to csv
    with open(out_file, 'w') as file:
        file.write("Commit date,Commit Hash\n")
        for commit in collected_commits:
            file.write(commit[0] + "," + commit[1] + "\n")


def main():
    # collect_commits("../mega-foss", "intervals/mega-foss.csv")
    # collect_commits("../FFmpeg", "intervals/ffmpeg.csv")
    local_repo = sys.argv[1]
    destination = sys.argv[2]
    collect_commits(local_repo, destination)

if __name__ == "__main__":
    main()