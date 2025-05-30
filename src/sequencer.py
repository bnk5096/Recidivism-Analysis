import thirty_day_commit_collector
import snapshot_to_patch
import complexity_collection
import sys

def all_coming_together(patch_vuln_file: str, cve_info_file: str, repo_location: str, repo_name: str, output_location: str):
    """ Combined run of thirty_day_commit_collector, snapshot_to_patch, and complexity_collection.

    Args:
        patch_vuln_file (str): JSONL file containing cves and patch data
        cve_info_file (str): cves mapped to involved files
        repo_location (str): location of the repo
        repo_name (str): name of the repo
        output_location (str): directory to write the complexity runs to
    """
    repo_name_sanitized = repo_name.replace("/", "_")
    snapshot_file = "intervals/" + repo_name_sanitized + ".csv"
    print("Running snapshot finder on " + repo_name + "...")
    thirty_day_commit_collector.collect_commits(repo_location, snapshot_file)
    print("Finding oldest relevant commit for " + repo_name + "...")
    oldest_patch = snapshot_to_patch.snapshot_to_patch(patch_vuln_file, repo_location, snapshot_file, repo_name)
    with open(snapshot_file) as file:
        print("Iterating through snapshots for " + repo_name + "...")
        now_running = False
        for line in file:
            data = line.split(",")
            if data[1] == oldest_patch:
                now_running = True
                print("Relevant snapshot now reached! Now running complexity for " + repo_name + "...")
            if now_running:
                date_no_time = data[0].split(" ")[0]
                complexity_out = output_location + "/" + repo_name_sanitized + "-" + date_no_time + ".csv"
                complexity_collection.run_scc(repo_location, complexity_out, cve_info_file, repo_name, data[1].strip())
    print("Finished " + repo_name + "!")

def main():
    patch_vuln_file = sys.argv[1]
    cve_info_file = sys.argv[2]
    repo_location = sys.argv[3]
    repo_name = sys.argv[4]
    output_location = sys.argv[5]
    all_coming_together(patch_vuln_file, cve_info_file, repo_location, repo_name, output_location)

if __name__ == "__main__":
    main()