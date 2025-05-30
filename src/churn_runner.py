import json
import sys
import churn_metrics

def churn_runner(repo_location: str, repo_cve_data: str, out_file: str, renames_file: str):
    """Gets the involved files to pass to the churn function, and then runs it.

    Args:
        repo_location (str): location of the repo
        repo_cve_data (str): repo cve data as found by the cve_match script
        out_file (str): destination for the final output
        renames_file (str): this repo's renames file
    """
    files = []
    with open(repo_cve_data) as data:
        cves = json.load(data)
        for cve in cves:
            for file in cve["patch_files"]:
                files.append(file)
            for file in cve["vuln_files"]:
                files.append(file)
    churn_metrics.churn(repo_location, files, out_file, renames_file)

def main():
    churn_runner(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])

if __name__ == "__main__":
    main()