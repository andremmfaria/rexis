import os

import pyghidra


def decompile_binary_with_pyghidra(binary_path: str):
    # Connect to Ghidra's headless server
    pyghidra.start()

    # Open the binary
    project_name = "MalwareAnalysisProject"
    project_path = "/path/to/ghidra_projects"  # You have to mount this in your Docker container
    full_project_path = os.path.join(project_path, project_name)

    # Import the binary into the project if needed
    program = pyghidra.open_program(project_location=full_project_path, program_name=binary_path)

    # Initialize the decompiler
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    decompiler = DecompInterface()
    decompiler.openProgram(program)

    fm = program.getFunctionManager()
    functions = fm.getFunctions(True)

    decompiled_functions = []
    monitor = ConsoleTaskMonitor()

    for func in functions:
        decomp_result = decompiler.decompileFunction(func, 60, monitor)
        if decomp_result.decompileCompleted():
            c_code = decomp_result.getDecompiledFunction().getC()
            decompiled_functions.append({"name": func.getName(), "code": c_code})

    # Clean up
    pyghidra.shutdown()

    return decompiled_functions


# Example usage
if __name__ == "__main__":
    binary_filename = "malware.exe"  # Assuming already imported
    results = decompile_binary_with_pyghidra(binary_filename)

    for func in results:
        print(f"Function: {func['name']}\n")
        print(func["code"])
        print("=" * 80)
