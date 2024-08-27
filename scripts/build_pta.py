import re, subprocess

prefix = "../linux-pta/"

# Replace the macro (e.g., EPERM, EACCES, EROFS) in the compilation error
# with the original error code (e.g., _EPERM, _EACCES, _EROFS).
def fix_compilation_errors_in_file(error_line):
    # Extract the file path and line number from the error message
    path_line_match = re.search(r'(.*):(\d+):(\d+):', error_line)
    if not path_line_match:
        print("Error: file path or line number not found in the provided message!")
        return
    filepath = prefix+path_line_match.group(1)
    line_number = int(path_line_match.group(2))
    col_number = int(path_line_match.group(3))

    # Define a dictionary to map the wrong macros to their correct values
    replacement_map = {
        'EPERM': '_EPERM',
        'EACCES': '_EACCES',
        'EROFS': '_EROFS'
    }

    # Read the file and fix the problematic line
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()

        # Check if line number is within file
        if line_number > len(lines):
            print(f"Error line number {line_number} exceeds the total lines in the file!")
            return
        if col_number > len(lines[line_number - 1]):
            print(f"Error column number {col_number} exceeds the total columns in the line!")

        fixed = False

        # Replace wrong macro in the problematic line
        print("Before: "+lines[line_number - 1])

        for i in range(col_number-1, len(lines[line_number - 1])):
            for wrong_macro, correct_macro in replacement_map.items():
                if lines[line_number - 1][i:].startswith(wrong_macro):
                    lines[line_number - 1] = lines[line_number-1][:i] + lines[line_number - 1][i:].replace(wrong_macro, correct_macro, 1)
                    fixed = True
                    break
            if fixed:
                break

        print("After: "+lines[line_number - 1])
        if not fixed:
            raise(Exception("No wrong macro found in the line!"))

        # Write the fixed lines back to the file
        with open(filepath, 'w') as f:
            f.writelines(lines)

        print(f"Fixed error in {filepath} at line {line_number}, col {col_number}!")

    except Exception as e:
        print(f"Error reading/writing the file {filepath}. Details: {e}")


def compile_and_fix():
    error_pattern = re.compile(r"^(?!ld\.lld).*error:.*")

    while True:
        # Compile the kernel
        process = subprocess.Popen("./build-kernel-pta.sh 2>&1", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        error_found = False
        for line in iter(process.stdout.readline, ''):
            print(line, end='')
            if error_pattern.match(line):
                error_found = True
                fix_compilation_errors_in_file(line)
                break

        process.stdout.close()
        return_code = process.wait()

        # If there's no error or the error is unexpected, break the loop
        if not return_code or not error_found:
            if not return_code:
                print("Compilation successful!")
            else:
                print("Error pattern not found in the compilation log!")
            break

# Start the process
compile_and_fix()
