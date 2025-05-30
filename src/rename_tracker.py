from git import Repo
import sys
import csv

# Tracks renames and writes rename history to a csv file.
# local_repo: repository directory
# out_file: destination file


def rename_tracker(local_repo, out_file):
    """ Tracks renames and generates a csv of all aliases of a file.

    Args:
        local_repo (str): repository directory
        out_file (str): destination file
    """
    repo = Repo(local_repo)
    git_cmd = repo.git
    # get renames only that are 50% or more similarity
    renames = git_cmd.execute(
        ['git', 'log', '--pretty=format:', '--name-status', '--find-renames=50', '--reverse', '--diff-filter=R'], stdout_as_string=True)
    renames_list = renames.split("\n")
    chains = []
    rename_records = []
    for line in renames_list:
        split_line = line.split("\t")
        # filter out extra spaces
        if len(split_line) != 3:
            continue
        old = split_line[1]
        new = split_line[2]
        flag = False
        # add items to chains
        for chain in chains:
            if old == chain[-1]:
                chain.append(new)
                flag = True
                break
        if not flag:
            chains.append([old, new])
    # add all chains to the main list
    for chain in chains:
        rename_records.append(tuple(chain))
    # write to file
    with open(out_file, "w+", newline='') as output_file:
        writer = csv.writer(output_file)
        for entry in rename_records:
            writer.writerow(entry)


def main():
    rename_tracker(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
