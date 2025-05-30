import sys

def repo_list_rebuild(old_file: str, to_be_removed: str, out_file: str):
    """Remove the single-cve repositories and generate a new list.

    Args:
        old_file (str): file containing repo master list
        to_be_removed (str): file containing repos to be excluded
        out_file (str): destination for new file
    """
    excludes = set()
    with open(to_be_removed) as file:
        for repo in file:
            excludes.add(repo.strip())
    with open(out_file, "+w") as out:
        with open(old_file) as old:
            for repo in old:
                if repo.strip() not in excludes:
                    out.write(repo.strip() + "\n")

def main():
    old_file = sys.argv[1]
    excludes = sys.argv[2]
    out = sys.argv[3]
    repo_list_rebuild(old_file, excludes, out)

if __name__ == "__main__":
    main()