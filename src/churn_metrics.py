import json
import csv
import sys
from git import Repo

def churn(repo_location: str, files: list, out_file: str, renames_file=""):
    """Calculates churn metrics. That's right, if you want it done right, do it yourself.
    Args:
        repo_location (str): repo location
        files (list): list of files to focus on. If empty, runs against all files.
        out_location (str): file to write results to
        renames_file (str): csv of file aliases so by file mode can track files across names. Not required in all file mode.
    """
    all_files_mode = False
    if len(files) == 0:
        print("All files: ON")
        all_files_mode = True
    file_set = set(files)
    if not all_files_mode:
        if renames_file == "":
            print("Error: File based mode used but renames file not specified. Quitting...")
            return
        with open(renames_file) as file:
            renames = csv.reader(file)
            for row in renames:
                for alias in row:
                    if alias in file_set:
                        file_set.update(row)
                        break
    churn_data = {}
    repo = Repo(repo_location)
    commit_iterator = None
    if all_files_mode:
        commit_iterator = repo.iter_commits(date_order=True)
    else:
        commit_iterator = repo.iter_commits(date_order=True, paths=file_set)
    most_recent_commit = next(commit_iterator)
    churn_data["base_commit"] = most_recent_commit.hexsha
    churn_data["commit_author"] = most_recent_commit.author.email
    churn_data["datetime"] = str(most_recent_commit.committed_datetime)
    print("Working commit " + churn_data["base_commit"] + " from " + churn_data["datetime"] + "...")
    try:
        churn_data["parent_commit"] = next(most_recent_commit.iter_parents()).hexsha
    except:
        churn_data["parent_commit"] = "parent not available"
    churn_data["metrics"] = []
    stats = most_recent_commit.stats
    for file in stats.files.keys():
        file_churn = {}
        if all_files_mode or file in file_set:
            print(file)
            print(str(stats.files[file]))
            file_churn["file_path"] = file
            file_churn["lines_added"] = stats.files[file]["insertions"]
            file_churn["lines_deleted"] = stats.files[file]["deletions"]
            file_churn["total_lines_changed"] = stats.files[file]["lines"]
            churn_data["metrics"].append(file_churn)
    churn_data["history"] = []
    for commit in commit_iterator:
        this_churn = {}
        this_churn["commit_id"] = commit.hexsha
        this_churn["commit_author"] = commit.author.email
        this_churn["datetime"] = str(commit.committed_datetime)
        print("Working commit " + this_churn["commit_id"] + " from " + this_churn["datetime"] + "...")
        try:
            this_churn["parent_commit"] = next(commit.iter_parents()).hexsha
        except:
            this_churn["parent_commit"] = "parent not available"
        this_churn["metrics"] = []
        stats = commit.stats
        for file in stats.files.keys():
            file_churn = {}
            if all_files_mode or file in file_set:
                file_churn["file_path"] = file
                file_churn["lines_added"] = stats.files[file]["insertions"]
                file_churn["lines_deleted"] = stats.files[file]["deletions"]
                file_churn["total_lines_changed"] = stats.files[file]["lines"]
                this_churn["metrics"].append(file_churn)
        if len(this_churn["metrics"]) != 0:
            churn_data["history"].append(this_churn)
    print("Writing to file...")
    with open(out_file, "w+", newline='') as out:
        json.dump(churn_data, out, indent=1)

def main():
    # churn(".", [], "git_churn_results/test_all.json")
    # churn(".", ["src/sequencer.py", "src/sequencer.slurm.sh"], "git_churn_results/test_some.json")
    # churn("../FFmpeg", [], "git_churn_results/test_FFmpeg_all.json")
    churn("../FFmpeg", ["libavutil/avstring.c"], "git_churn_results/test_FFmpeg_one_file_iteration_fixed.json", "renames/ffmpeg.csv")

if __name__ == "__main__":
    main()