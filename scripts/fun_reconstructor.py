import os
import re
import subprocess


def extract_file_index(content):
    match = re.search(r"//file(\d+)", content)
    if match:
        return int(match.group(1))
    return float("inf")  # If no match, put it at the end


def reconstruct_program(directory):
    print(f"Reconstructing program...")
    program_parts = []

    for filename in os.listdir(directory):
        if filename.endswith(".pcap"):
            with open(os.path.join(directory, filename), "r") as file:
                content = file.read()
                file_index = extract_file_index(content)
                program_parts.append((file_index, content))

    # Sort based on the file index extracted from the comment
    program_parts.sort()

    # Combine the sorted parts into one single program
    complete_program = ""
    for _, part in program_parts:
        complete_program += part + "\n"

    return complete_program


def remove_comments(complete_program):
    print(f"Removing useless_function()s and comments...")
    pattern = r"/\*.*?\*/"
    cleaned_program = re.sub(pattern, "", complete_program, flags=re.DOTALL)
    return cleaned_program


def save_program(complete_program, output_filename):
    with open(output_filename, "w") as file:
        file.write(complete_program)


def compile_program(source_file, executable_file):
    try:
        subprocess.run(["gcc", source_file, "-o", executable_file], check=True)
        print(f"Compilation successful. Executable created: {executable_file}")
    except subprocess.CalledProcessError as e:
        print(f"Compilation failed: {e}")


def execute_program(executable_file):
    try:
        result = subprocess.run(
            [f"./{executable_file}"], capture_output=True, text=True
        )
        print(f"Program output:\n{result.stdout}")
        if result.stderr:
            print(f"Program errors:\n{result.stderr}")
    except Exception as e:
        print(f"Execution failed: {e}")


if __name__ == "__main__":
    directory = "ft_fun"  # directory containing .pcap files
    source_file = "reconstructed_program.c"
    executable_file = "reconstructed_program"

    complete_program = reconstruct_program(directory)
    cleaned_program = remove_comments(complete_program)
    save_program(cleaned_program, source_file)

    compile_program(source_file, executable_file)
    execute_program(executable_file)
