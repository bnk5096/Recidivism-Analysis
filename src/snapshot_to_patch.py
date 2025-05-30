from git import Repo
from datetime import datetime, timezone
import json
import sys

def snapshot_to_patch(patches: str, local_repo: str, snapshots: str, repo_name: str):
    """ Takes a snapshot file, a patch file, and a repo and identifies the snapshot
    just before the earliest patch.

    Args:
        patches (str): path to patch file
        local_repo (str): repo location
        snapshots (str): path to snapshot file
        repo_name (str): name of the repo
    """
    # load in all possible target dates
    target_dates = []
    commit_hashes = []
    with open(snapshots) as snapshot_file:
        snapshot_file.readline()
        for line in snapshot_file:
            target_dates.append(datetime.fromisoformat(line.split(",")[0]))
            commit_hashes.append(line.split(",")[1])
    repo = Repo(local_repo)
    oldest_commit_date = datetime.now(timezone(target_dates[0].utcoffset()))
    with open(patches, 'r') as patch_file:
        for line in patch_file:
            patch = json.loads(line)
            # if not relevant to this repo, skip
            if patch["repo"] != repo_name:
                continue
            current_commit = repo.commit(patch["patch_commit"])
            current_commit_date = current_commit.committed_datetime
            if current_commit_date < oldest_commit_date:
                oldest_commit_date = current_commit_date
    result_commit = ""
    for i in range(len(target_dates) - 1, -1, -1):
        if oldest_commit_date < target_dates[i]:
            try:
                result_commit = commit_hashes[i - 1]
            except:
                # should never occur if snapshot and patch files are formatted properly, but just in case
                print("Patch commit occurs before first snapshot")
                return
    return result_commit

def main():
    # print(snapshot_to_patch("..\mega-foss\src\slurm\drill_scripts\production_ready\patch_vuln_match.jsonl", "../FFmpeg", "intervals/FFmpeg.csv", "FFmpeg/FFmpeg"))
    patch_vuln_file = sys.argv[1]
    local_repo = sys.argv[2]
    snapshots_file = sys.argv[3]
    repo_name = sys.argv[4]
    result = snapshot_to_patch(patch_vuln_file, local_repo, snapshots_file, repo_name)
    print(result)

if __name__ == "__main__":
    main()
