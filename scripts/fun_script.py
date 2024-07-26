import os
import re

def get_file_number(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            match = re.search(r'//file(\d+)', line)
            if match:
                return int(match.group(1))
    return None

def sort_files_by_number(directory):
    files_with_numbers = []

    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        if os.path.isfile(file_path):
            file_number = get_file_number(file_path)
            if file_number is not None:
                files_with_numbers.append((file_number, file_name))

    sorted_files = sorted(files_with_numbers, key=lambda x: x[0])
    sorted_file_names = [file_name for _, file_name in sorted_files]

    return sorted_file_names

directory_path = 'ft_fun'  # Replace with the path to your directory
sorted_files = sort_files_by_number(directory_path)

#for file in sorted_files:
#    print(file)

for file in sorted_files:
    f = open("ft_fun/" + file, 'r')
    content = f.read()
    if "return" in content:
        print(content)
    f.close

