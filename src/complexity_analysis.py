import csv
import matplotlib.pyplot as plt

def complexity_grapher(repo_name: str, complexity_file: str, output_folder: str):
    """ Creates 4 complexity graphs: lines over time, unique lines over time,
        complexity per line over time, and complexity per unique line over time.

        Args:
            repo_name (str): name of the repository
            complexity_file (str): csv file containing complexity data
            output_folder (str): folder to save graphs to
    """
    repo_name_no_slash = repo_name.replace("/", "_")
    dates = []
    lines = []
    ulines = []
    complexity_per_line = []
    complexity_per_uline = []
    with open(complexity_file, newline='') as comp_file:
        csv_reader = csv.reader(comp_file)
        for row in csv_reader:
            dates.append(row[0])
            lines.append(row[1])
            ulines.append(row[2])
            complexity_per_line.append(row[4])
            complexity_per_uline.append(row[5])
    # Lines over time
    plt.figure()
    plt.plot(dates, lines, label="Lines")
    plt.xlabel("Snapshot")
    plt.ylabel("Lines")
    plt.title(f"{repo_name} Lines Over Time")
    plt.legend()
    plt.savefig(f"{output_folder}/{repo_name_no_slash}_lines.png")
    # Ulines over time
    plt.figure()
    plt.plot(dates, ulines, label="Unique Lines")
    plt.xlabel("Snapshot")
    plt.ylabel("Unique Lines")
    plt.title(f"{repo_name} Unique Lines Over Time")
    plt.legend()
    plt.savefig(f"{output_folder}/{repo_name_no_slash}_ulines.png")
    # Complexity per line over time
    plt.figure()
    plt.plot(dates, complexity_per_line, label="Complexity per Line")
    plt.xlabel("Snapshot")
    plt.ylabel("Complexity per Line")
    plt.title(f"{repo_name} Complexity per Line Over Time")
    plt.legend()
    plt.savefig(f"{output_folder}/{repo_name_no_slash}_cpl.png")
    # Complexity per uline over time
    plt.figure()
    plt.plot(dates, complexity_per_uline, label="Complexity per Unique Line")
    plt.xlabel("Snapshot")
    plt.ylabel("Complexity per Unique Line")
    plt.title(f"{repo_name} Complexity per Unique Line Over Time")
    plt.legend()
    plt.savefig(f"{output_folder}/{repo_name_no_slash}_cpu.png")
