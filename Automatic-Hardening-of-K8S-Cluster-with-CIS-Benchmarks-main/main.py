import subprocess
import sys
import paramiko
import warnings
from collections import OrderedDict
from remediate import *




def validate_cluster():
    """Validates the Kubernetes cluster using kops."""
    command = "kops validate cluster --state=s3://cistest-kops-stateholder"
    try:
        result = subprocess.run(command.split(), check=True, capture_output=True, text=True)
        print("Kubernetes Cluster Validated")
        print("\n")
    except subprocess.CalledProcessError as err:
        
        return False
    return True

def configure(ssh_username,ssh_key_file):
    name=input("Enter the username of Cluster Nodes:")
    ssh_username=name
    print("\n")
    key_file=input("Enter filename of the key to ssh into Cluster Nodes:")
    ssh_key_file=key_file
    print("\n")

def retrieve_node_ips():
    """Retrieves the public IP addresses of nodes using kubectl."""
    command = "kubectl get nodes -o wide"
    result = subprocess.run(command.split(), check=True, capture_output=True, text=True)
    output=result.stdout.splitlines()
    output=output[1:]
    node_ips = []
    for line in output:
        if 'control-plane' in line:
            fields = line.split()  
            external_ip = fields[6]
            node_ips.append(external_ip)
    for line in output:
        fields = line.split()  
        external_ip = fields[6]
        node_ips.append(external_ip)


    return node_ips


def remove_exempt_items(failed, exempt):
    
    return [item for item in failed if item not in exempt]

def install_kube_bench_worker(node_ip, ssh_username, ssh_key_file):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy)
    warnings.filterwarnings("ignore")

    # ... (SSH connection setup remains the same)
    try:
        client.connect(node_ip, username=ssh_username, key_filename=ssh_key_file)

        # Install kube-bench commands
        commands = [
            "curl -LO https://github.com/aquasecurity/kube-bench/releases/download/v0.6.8/kube-bench_0.6.8_linux_amd64.tar.gz",
            "sudo mkdir -p /etc/kube-bench",
            "sudo tar -xvf kube-bench_0.6.8_linux_amd64.tar.gz -C /etc/kube-bench",
            "sudo mv /etc/kube-bench/kube-bench /usr/local/bin"
        ]
        for command in commands:
            stdin, stdout, stderr = client.exec_command(command)
            #print(f"Output for command '{command}':\n{stdout.read().decode()}")  # Print output for each command

        run_command = "kube-bench"

        # Run the command and capture its output
        #result = subprocess.run(run_command, shell=True, capture_output=True, text=True)
        stdin,stdout,stderr=client.exec_command(run_command)

        # The stdout attribute contains the output
        log = stdout.read().decode()
        lines = log.split('\n')

        # Initialize an empty list to store the failed benchmarks
        failed_benchmarks = []
        print("\n")
        print("-----------------------------------------------")
        print(f"Failed Benchmarks for Worker Node ({node_ip}):")
        print("-----------------------------------------------")
        print("\n")
        # Iterate over each line in the log
        for line in lines:
            # If the line represents a failed benchmark
            if '[FAIL]' in line:
                # Extract the benchmark number
                benchmark_number = line.split(' ')[1]
                # Add the benchmark number to the list
                failed_benchmarks.append(benchmark_number)
                print(line)  

        try:
            exempted_controls=[]
            with open("exempt.txt",'r') as file:
                lines=file.readlines()
                exempted_controls=[line.strip() for line in lines]
                failed_benchmarks=remove_exempt_items(failed_benchmarks,exempted_controls)
    

        except Exception as e:
            print(f"Error:{e}")        

        remediated_controls=[]
        print("\n")
        value=input("Do you want to remediate the controls on Worker Node[y/N]: ")
        if value=="y" or value=="Y":
            for number in failed_benchmarks:
                if number=="4.1.1":
                    cis_4_1_1(client,remediated_controls)
                if number=="4.1.2":
                    cis_4_1_2(client,remediated_controls)  
                if number=="4.1.5":
                    cis_4_1_5(client,remediated_controls)
                if number=="4.1.6":
                    cis_4_1_6(client,remediated_controls)
                if number=="4.1.9":
                    cis_4_1_9(client,remediated_controls)  
                if number=="4.1.10":
                    cis_4_1_10(client,remediated_controls)
                if number=="4.2.1":
                    cis_4_2_1(client,remediated_controls)
                if number=="4.2.2":
                    cis_4_2_2(client,remediated_controls)  
                if number=="4.2.3":
                    cis_4_2_3(client,remediated_controls) 
                if number=="4.2.6":
                    cis_4_2_6(client,remediated_controls)
                if number=="4.2.7":
                    cis_4_2_7(client,remediated_controls)  
                if number=="4.2.11":
                    cis_4_2_11(client,remediated_controls)
                if number=="5.2.3":
                    cis_5_2_3(client,remediated_controls)
                if number=="5.2.4":
                    cis_5_2_4(client,remediated_controls)
                if number=="5.2.5":
                    cis_5_2_5(client,remediated_controls)  
                if number=="5.2.6":
                    cis_5_2_6(client,remediated_controls) 
                if number=="5.2.7":
                    cis_5_2_7(client,remediated_controls)
                if number=="5.2.8":
                    cis_5_2_8(client,remediated_controls)  
                if number=="5.2.9":
                    cis_5_2_9(client,remediated_controls)

            print("\n")
            print("-----------------------------------------------")
            print(f"Remediated Controls for {node_ip}:")
            print("-----------------------------------------------")
            print("\n")
            for number in remediated_controls:  
                print(number)          

        else:
            print("Remediation is skipped") 
            return               
        
                  


    except Exception as err:
        print(f"Failed to install kube-bench on {node_ip}: {err}")
    finally:
        client.close()

def install_kube_bench_worker_all(node_ip, ssh_username, ssh_key_file):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy)
    warnings.filterwarnings("ignore")

    # ... (SSH connection setup remains the same)
    try:
        client.connect(node_ip, username=ssh_username, key_filename=ssh_key_file)

        # Install kube-bench commands
        commands = [
            "curl -LO https://github.com/aquasecurity/kube-bench/releases/download/v0.6.8/kube-bench_0.6.8_linux_amd64.tar.gz",
            "sudo mkdir -p /etc/kube-bench",
            "sudo tar -xvf kube-bench_0.6.8_linux_amd64.tar.gz -C /etc/kube-bench",
            "sudo mv /etc/kube-bench/kube-bench /usr/local/bin"
        ]
        for command in commands:
            stdin, stdout, stderr = client.exec_command(command)
            #print(f"Output for command '{command}':\n{stdout.read().decode()}")  # Print output for each command

        run_command = "kube-bench"

        # Run the command and capture its output
        result = subprocess.run(run_command, shell=True, capture_output=True, text=True)
        stdin,stdout,stderr=client.exec_command(run_command)

        # The stdout attribute contains the output
        log = stdout.read().decode()
        lines = log.split('\n')

        # Initialize an empty list to store the failed benchmarks
        failed_benchmarks = []
        warn_manual_benchmarks = []
        print("\n")
        print("-----------------------------------------------")
        print(f"Failed Benchmarks for Worker Node ({node_ip}):")
        print("-----------------------------------------------")
        print("\n")
        # Iterate over each line in the log
        for line in lines:
            # If the line represents a failed benchmark
            if '[FAIL]' in line:
                # Extract the benchmark number
                benchmark_number = line.split(' ')[1]
                # Add the benchmark number to the list
                failed_benchmarks.append(benchmark_number)
                print(line) 

            if '[WARN]' in line:
                
                # Extract the benchmark number
                benchmark_number = line.split(' ')[1]
                # Add the benchmark number to the list
                warn_manual_benchmarks.append(benchmark_number)
                print(line) 

        try:
            exempted_controls=[]
            with open("exempt.txt",'r') as file:
                lines=file.readlines()
                exempted_controls=[line.strip() for line in lines]
                failed_benchmarks=remove_exempt_items(failed_benchmarks,exempted_controls)
                


        except Exception as e:
            print(f"Error:{e}")        

        remediated_controls=[]
        print_manual_benchmarks=[]
        print("\n")
        value=input("Do you want to remediate the controls on Worker Node[y/N]: ")
        if value=="y" or value=="Y":
            for number in failed_benchmarks:

                if number=="4.1.1":
                    cis_4_1_1(client,remediated_controls)
                if number=="4.1.2":
                    cis_4_1_2(client,remediated_controls)  
                if number=="4.1.5":
                    cis_4_1_5(client,remediated_controls)
                if number=="4.1.6":
                    cis_4_1_6(client,remediated_controls)
                if number=="4.1.9":
                    cis_4_1_9(client,remediated_controls)  
                if number=="4.1.10":
                    cis_4_1_10(client,remediated_controls)
                if number=="4.2.1":
                    cis_4_2_1(client,remediated_controls)
                if number=="4.2.2":
                    cis_4_2_2(client,remediated_controls)  
                if number=="4.2.3":
                    cis_4_2_3(client,remediated_controls) 
                if number=="4.2.6":
                    cis_4_2_6(client,remediated_controls)
                if number=="4.2.7":
                    cis_4_2_7(client,remediated_controls)  
                if number=="4.2.11":
                    cis_4_2_11(client,remediated_controls)
                if number=="5.2.3":
                    cis_5_2_3(client,remediated_controls)
                if number=="5.2.4":
                    cis_5_2_4(client,remediated_controls)
                if number=="5.2.5":
                    cis_5_2_5(client,remediated_controls)  
                if number=="5.2.6":
                    cis_5_2_6(client,remediated_controls) 
                if number=="5.2.7":
                    cis_5_2_7(client,remediated_controls)
                if number=="5.2.8":
                    cis_5_2_8(client,remediated_controls)  
                if number=="5.2.9":
                    cis_5_2_9(client,remediated_controls)


            print("\n")
            print("-----------------------------------------------")
            print(f"Remediated Controls for {node_ip}:")
            print("-----------------------------------------------")
            print("\n")
            for number in remediated_controls:  
                print(number) 


            for number in warn_manual_benchmarks:
                if number=="4.1.3":
                    cis_4_1_3(print_manual_benchmarks)
                if number=="4.1.4":
                    cis_4_1_4(print_manual_benchmarks)
                if number=="4.1.7":
                    cis_4_1_7(print_manual_benchmarks)
                if number=="4.1.8":
                    cis_4_1_8(print_manual_benchmarks)
                if number=="4.2.4":
                    cis_4_2_4(print_manual_benchmarks)
                if number=="4.2.5":
                    cis_4_2_5(print_manual_benchmarks)
                if number=="4.2.8":
                    cis_4_2_8(print_manual_benchmarks)
                if number=="4.2.9":
                    cis_4_2_9(print_manual_benchmarks)
                if number=="4.2.10":
                    cis_4_2_10(print_manual_benchmarks)
                if number=="4.2.12":
                    cis_4_2_12(print_manual_benchmarks)
                if number=="4.2.13":
                    cis_4_2_13(print_manual_benchmarks)
                if number=="5.1.1":
                    cis_5_1_1(print_manual_benchmarks)
                if number=="5.1.2":
                    cis_5_1_2(print_manual_benchmarks)
                if number=="5.1.3":
                    cis_5_1_3(print_manual_benchmarks)
                if number=="5.1.4":
                    cis_5_1_4(print_manual_benchmarks)
                if number=="5.1.5":
                    cis_5_1_5(print_manual_benchmarks)
                if number=="5.1.6":
                    cis_5_1_6(print_manual_benchmarks)
                if number=="5.1.7":
                    cis_5_1_7(print_manual_benchmarks)
                if number=="5.1.8":
                    cis_5_1_8(print_manual_benchmarks)
                if number=="5.1.9":
                    cis_5_1_9(print_manual_benchmarks)
                if number=="5.1.10":
                    cis_5_1_10(print_manual_benchmarks)

                if number=="5.1.11":
                    cis_5_1_11(print_manual_benchmarks)
                if number=="5.1.12":
                    cis_5_1_12(print_manual_benchmarks)
                if number=="5.1.13":
                    cis_5_1_13(print_manual_benchmarks)
                if number=="5.2.1":
                    cis_5_2_1(print_manual_benchmarks)
                if number=="5.2.2":
                    cis_5_2_2(print_manual_benchmarks)
                if number=="5.2.10":
                    cis_5_2_10(print_manual_benchmarks)
                if number=="5.2.11":
                    cis_5_2_11(print_manual_benchmarks)
                if number=="5.2.12":
                    cis_5_2_12(print_manual_benchmarks)
                if number=="5.2.13":
                    cis_5_2_13(print_manual_benchmarks)
                if number=="5.3.1":
                    cis_5_3_1(print_manual_benchmarks)
                if number=="5.3.2":
                    cis_5_3_2(print_manual_benchmarks)
                if number=="5.4.1":
                    cis_5_4_1(print_manual_benchmarks)
                if number=="5.4.2":
                    cis_5_4_2(print_manual_benchmarks)
                if number=="5.5.1":
                    cis_5_5_1(print_manual_benchmarks)
                if number=="5.7.1":
                    cis_5_7_1(print_manual_benchmarks)
                if number=="5.7.2":
                    cis_5_7_2(print_manual_benchmarks)
                if number=="5.7.3":
                    cis_5_7_3(print_manual_benchmarks)
                if number=="5.7.4":
                    cis_5_7_4(print_manual_benchmarks)

                        

            print("\n")
            print("------------------------------------------------------------------")
            print(f"Manual Steps to Remediate Controls for Worker Node ({node_ip}):")
            print("------------------------------------------------------------------")
            print("\n")
            for number in print_manual_benchmarks:
                print(number)
                    

        else:
            print("Remediation is skipped") 
            return               
        
                   


    except Exception as err:
        print(f"Failed to install kube-bench on {node_ip}: {err}")
    finally:
        client.close()


def install_kube_bench_master(node_ip, ssh_username, ssh_key_file):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy)
    warnings.filterwarnings("ignore")

    # ... (SSH connection setup remains the same)
    try:
        client.connect(node_ip, username=ssh_username, key_filename=ssh_key_file)

        # Install kube-bench commands
        commands = [
            "curl -LO https://github.com/aquasecurity/kube-bench/releases/download/v0.6.8/kube-bench_0.6.8_linux_amd64.tar.gz",
            "sudo mkdir -p /etc/kube-bench",
            "sudo tar -xvf kube-bench_0.6.8_linux_amd64.tar.gz -C /etc/kube-bench",
            "sudo mv /etc/kube-bench/kube-bench /usr/local/bin"
        ]
        for command in commands:
            stdin, stdout, stderr = client.exec_command(command)
            #print(f"Output for command '{command}':\n{stdout.read().decode()}")  # Print output for each command

        run_command = "kube-bench"

        # Run the command and capture its output
        #result = subprocess.run(run_command, shell=True, capture_output=True, text=True)
        stdin,stdout,stderr=client.exec_command(run_command)

        # The stdout attribute contains the output
        log = stdout.read().decode()
        lines = log.split('\n')

        # Initialize an empty list to store the failed benchmarks
        failed_benchmarks = []
        print("\n")
        print("-----------------------------------------------")
        print(f"Failed Benchmarks for Master Node ({node_ip}):")
        print("-----------------------------------------------")
        print("\n")
        # Iterate over each line in the log
        for line in lines:
            # If the line represents a failed benchmark
            if '[FAIL]' in line:
                
                # Extract the benchmark number
                benchmark_number = line.split(' ')[1]
                # Add the benchmark number to the list
                failed_benchmarks.append(benchmark_number)
                print(line) 
            if '3 Control Plane Configuration' in line:
                break  

        try:
            exempted_controls=[]
            with open("exempt.txt",'r') as file:
                lines=file.readlines()
                exempted_controls=[line.strip() for line in lines]
                failed_benchmarks=remove_exempt_items(failed_benchmarks,exempted_controls)
                

        except Exception as e:
            print(f"Error:{e}")





        remediated_controls=[]
        print("\n")
        value=input("Do you want to remediate the controls on Master Node[y/N]: ")
        if value=="y" or value=="Y":
            for number in failed_benchmarks:
                if number=="1.1.1":
                    cis_1_1_1(client,remediated_controls)
                if number=="1.1.2":
                    cis_1_1_2(client,remediated_controls)
                if number=="1.1.3":
                    cis_1_1_3(client,remediated_controls)
                if number=="1.1.4":
                    cis_1_1_4(client,remediated_controls)
                if number=="1.1.5":
                    cis_1_1_5(client,remediated_controls)
                if number=="1.1.6":
                    cis_1_1_6(client,remediated_controls)
                if number=="1.1.7":
                    cis_1_1_7(client,remediated_controls)
                if number=="1.1.8":
                    cis_1_1_8(client,remediated_controls)
                if number=="1.1.11":
                    cis_1_1_11(client,remediated_controls)
                if number=="1.1.12":
                    cis_1_1_12(client,remediated_controls) 
                if number=="1.1.13":
                    cis_1_1_13(client,remediated_controls)
                if number=="1.1.14":
                    cis_1_1_14(client,remediated_controls)
                if number=="1.1.15":
                    cis_1_1_15(client,remediated_controls)
                if number=="1.1.16":
                    cis_1_1_16(client,remediated_controls)
                if number=="1.1.17":
                    cis_1_1_17(client,remediated_controls)
                if number=="1.1.18":
                    cis_1_1_18(client,remediated_controls)
                if number=="1.1.19":
                    cis_1_1_19(client,remediated_controls)
                if number=="1.2.2":
                    cis_1_2_2(client,remediated_controls)
                if number=="1.2.4":
                    cis_1_2_4(client,remediated_controls)
                if number=="1.2.5":
                    cis_1_2_5(client,remediated_controls)
                if number=="1.2.6":
                    cis_1_2_6(client,remediated_controls)
                if number=="1.2.7":
                    cis_1_2_7(client,remediated_controls)
                if number=="1.2.8":
                    cis_1_2_8(client,remediated_controls)
                if number=="1.2.9":
                    cis_1_2_9(client,remediated_controls)
                if number=="1.2.11":
                    cis_1_2_11(client,remediated_controls)
                if number=="1.2.14":
                    cis_1_2_14(client,remediated_controls)
                if number=="1.2.15":
                    cis_1_2_15(client,remediated_controls)
                if number=="1.2.16":
                    cis_1_2_16(client,remediated_controls)
                if number=="1.2.17":
                    cis_1_2_17(client,remediated_controls)
                if number=="1.2.18":
                    cis_1_2_18(client,remediated_controls)
                if number=="1.2.19":
                    cis_1_2_19(client,remediated_controls)
                if number=="1.2.20":
                    cis_1_2_20(client,remediated_controls)
                if number=="1.2.21":
                    cis_1_2_21(client,remediated_controls)
                if number=="1.2.22":
                    cis_1_2_22(client,remediated_controls)
                if number=="1.2.24":
                    cis_1_2_24(client,remediated_controls)
                if number=="1.2.25":
                    cis_1_2_25(client,remediated_controls)
                if number=="1.2.26":
                    cis_1_2_26(client,remediated_controls)
                if number=="1.2.27":
                    cis_1_2_27(client,remediated_controls)
                if number=="1.2.28":
                    cis_1_2_28(client,remediated_controls)
                if number=="1.2.29":
                    cis_1_2_29(client,remediated_controls)
                if number=="1.3.2":
                    cis_1_3_2(client,remediated_controls)
                if number=="1.3.3":
                    cis_1_3_3(client,remediated_controls)
                if number=="1.3.4":
                    cis_1_3_4(client,remediated_controls)
                if number=="1.3.5":
                    cis_1_3_5(client,remediated_controls)
                if number=="1.3.6":
                    cis_1_3_6(client,remediated_controls)
                if number=="1.3.7":
                    cis_1_3_7(client,remediated_controls)
                if number=="1.4.1":
                    cis_1_4_1(client,remediated_controls)
                if number=="1.4.2":
                    cis_1_4_2(client,remediated_controls)
                

            print("\n")
            print("-----------------------------------------------")
            print(f"Remediated Controls for {node_ip}:")
            print("-----------------------------------------------")
            print("\n")
            for number in remediated_controls:  
                print(number)  
        
        else:
            print("Remediation is skipped")
            return

    except Exception as err:
        print(f"Failed to install kube-bench on {node_ip}: {err}")
    finally:
        client.close()


def install_kube_bench_master_all(node_ip, ssh_username, ssh_key_file):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy)
    warnings.filterwarnings("ignore")

    # ... (SSH connection setup remains the same)
    try:
        client.connect(node_ip, username=ssh_username, key_filename=ssh_key_file)

        # Install kube-bench commands
        commands = [
            "curl -LO https://github.com/aquasecurity/kube-bench/releases/download/v0.6.8/kube-bench_0.6.8_linux_amd64.tar.gz",
            "sudo mkdir -p /etc/kube-bench",
            "sudo tar -xvf kube-bench_0.6.8_linux_amd64.tar.gz -C /etc/kube-bench",
            "sudo mv /etc/kube-bench/kube-bench /usr/local/bin"
        ]
        for command in commands:
            stdin, stdout, stderr = client.exec_command(command)
            #print(f"Output for command '{command}':\n{stdout.read().decode()}")  # Print output for each command

        run_command = "kube-bench"

        # Run the command and capture its output
        result = subprocess.run(run_command, shell=True, capture_output=True, text=True)
        stdin,stdout,stderr=client.exec_command(run_command)

        # The stdout attribute contains the output
        log = stdout.read().decode()
        lines = log.split('\n')

        # Initialize an empty list to store the failed benchmarks
        failed_benchmarks = []
        warn_manual_benchmarks=[]
        print("\n")
        print("-----------------------------------------------")
        print(f"Failed Benchmarks for Master Node ({node_ip}):")
        print("-----------------------------------------------")
        print("\n")
        # Iterate over each line in the log
        for line in lines:
            # If the line represents a failed benchmark
            if '[FAIL]' in line:
                
                # Extract the benchmark number
                benchmark_number = line.split(' ')[1]
                # Add the benchmark number to the list
                failed_benchmarks.append(benchmark_number)
                print(line)   
            
            if '[WARN]' in line:
                
                # Extract the benchmark number
                benchmark_number = line.split(' ')[1]
                # Add the benchmark number to the list
                warn_manual_benchmarks.append(benchmark_number)
                print(line)
             
            if '3 Control Plane Configuration' in line:
                break 


        try:
            exempted_controls=[]
            with open("exempt.txt",'r') as file:
                lines=file.readlines()
                exempted_controls=[line.strip() for line in lines]
                failed_benchmarks=remove_exempt_items(failed_benchmarks,exempted_controls)
                

        except Exception as e:
            print(f"Error:{e}")  

        remediated_controls=[]
        print_manual_benchmarks=[]
        print("\n")
        value=input("Do you want to remediate the controls on Master Node[y/N]: ")
        if value=="y" or value=="Y":
            for number in failed_benchmarks:
                
                if number=="1.1.1":
                    cis_1_1_1(client,remediated_controls)
                if number=="1.1.2":
                    cis_1_1_2(client,remediated_controls)
                if number=="1.1.3":
                    cis_1_1_3(client,remediated_controls)
                if number=="1.1.4":
                    cis_1_1_4(client,remediated_controls)
                if number=="1.1.5":
                    cis_1_1_5(client,remediated_controls)
                if number=="1.1.6":
                    cis_1_1_6(client,remediated_controls)
                if number=="1.1.7":
                    cis_1_1_7(client,remediated_controls)
                if number=="1.1.8":
                    cis_1_1_8(client,remediated_controls)
                if number=="1.1.11":
                    cis_1_1_11(client,remediated_controls)
                if number=="1.1.12":
                    cis_1_1_12(client,remediated_controls) 
                if number=="1.1.13":
                    cis_1_1_13(client,remediated_controls)
                if number=="1.1.14":
                    cis_1_1_14(client,remediated_controls)
                if number=="1.1.15":
                    cis_1_1_15(client,remediated_controls)
                if number=="1.1.16":
                    cis_1_1_16(client,remediated_controls)
                if number=="1.1.17":
                    cis_1_1_17(client,remediated_controls)
                if number=="1.1.18":
                    cis_1_1_18(client,remediated_controls)
                if number=="1.1.19":
                    cis_1_1_19(client,remediated_controls)
                if number=="1.2.2":
                    cis_1_2_2(client,remediated_controls)
                if number=="1.2.4":
                    cis_1_2_4(client,remediated_controls)
                if number=="1.2.5":
                    cis_1_2_5(client,remediated_controls)
                if number=="1.2.6":
                    cis_1_2_6(client,remediated_controls)
                if number=="1.2.7":
                    cis_1_2_7(client,remediated_controls)
                if number=="1.2.8":
                    cis_1_2_8(client,remediated_controls)
                if number=="1.2.9":
                    cis_1_2_9(client,remediated_controls)
                if number=="1.2.11":
                    cis_1_2_11(client,remediated_controls)
                if number=="1.2.14":
                    cis_1_2_14(client,remediated_controls)
                if number=="1.2.15":
                    cis_1_2_15(client,remediated_controls)
                if number=="1.2.16":
                    cis_1_2_16(client,remediated_controls)
                if number=="1.2.17":
                    cis_1_2_17(client,remediated_controls)
                if number=="1.2.18":
                    cis_1_2_18(client,remediated_controls)
                if number=="1.2.19":
                    cis_1_2_19(client,remediated_controls)
                if number=="1.2.20":
                    cis_1_2_20(client,remediated_controls)
                if number=="1.2.21":
                    cis_1_2_21(client,remediated_controls)
                if number=="1.2.22":
                    cis_1_2_22(client,remediated_controls)
                if number=="1.2.24":
                    cis_1_2_24(client,remediated_controls)
                if number=="1.2.25":
                    cis_1_2_25(client,remediated_controls)
                if number=="1.2.26":
                    cis_1_2_26(client,remediated_controls)
                if number=="1.2.27":
                    cis_1_2_27(client,remediated_controls)
                if number=="1.2.28":
                    cis_1_2_28(client,remediated_controls)
                if number=="1.2.29":
                    cis_1_2_29(client,remediated_controls)
                if number=="1.3.2":
                    cis_1_3_2(client,remediated_controls)
                if number=="1.3.3":
                    cis_1_3_3(client,remediated_controls)
                if number=="1.3.4":
                    cis_1_3_4(client,remediated_controls)
                if number=="1.3.5":
                    cis_1_3_5(client,remediated_controls)
                if number=="1.3.6":
                    cis_1_3_6(client,remediated_controls)
                if number=="1.3.7":
                    cis_1_3_7(client,remediated_controls)
                if number=="1.4.1":
                    cis_1_4_1(client,remediated_controls)
                if number=="1.4.2":
                    cis_1_4_2(client,remediated_controls)
        
            print("\n")
            print("-----------------------------------------------")
            print(f"Remediated Controls for {node_ip}:")
            print("-----------------------------------------------")
            print("\n")
            for number in remediated_controls:  
                print(number)  

            for number in warn_manual_benchmarks:
                if number=="1.1.9":
                    cis_1_1_9(print_manual_benchmarks)
                if number=="1.1.10":
                    cis_1_1_10(print_manual_benchmarks)  
                if number=="1.1.20":
                    cis_1_1_20(print_manual_benchmarks)
                if number=="1.1.21":
                    cis_1_1_21(print_manual_benchmarks)
                if number=="1.2.1":
                    cis_1_2_1(print_manual_benchmarks)  
                if number=="1.2.3":
                    cis_1_2_3(print_manual_benchmarks)  
                if number=="1.2.10":
                    cis_1_2_10(print_manual_benchmarks)
                if number=="1.2.12":
                    cis_1_2_12(print_manual_benchmarks)  
                if number=="1.2.13":
                    cis_1_2_13(print_manual_benchmarks)
                if number=="1.2.23":
                    cis_1_2_23(print_manual_benchmarks)
                if number=="1.2.30":
                    cis_1_2_30(print_manual_benchmarks)  
                if number=="1.2.31":
                    cis_1_2_31(print_manual_benchmarks)
                if number=="1.2.32":
                    cis_1_2_32(print_manual_benchmarks)
                if number=="1.3.1":
                    cis_1_3_1(print_manual_benchmarks)  
                if number=="2.7":
                    cis_2_7(print_manual_benchmarks)
                if number=="3.1.1":
                    cis_3_1_1(print_manual_benchmarks)
                if number=="3.1.2":
                    cis_3_1_2(print_manual_benchmarks)  
                if number=="3.1.3":
                    cis_3_1_3(print_manual_benchmarks)
                if number=="3.2.1":
                    cis_3_2_1(print_manual_benchmarks)
                if number=="3.2.2":
                    cis_3_2_2(print_manual_benchmarks)  
                if number=="1.1.9":
                    cis_1_1_9(print_manual_benchmarks)
                

            print("\n")
            print("------------------------------------------------------------------")
            print(f"Manual Steps to Remediate Controls for Master Node ({node_ip}):")
            print("------------------------------------------------------------------")
            print("\n")
            for number in print_manual_benchmarks:
                print(number)
        
        else:
            print("Remediation is skipped")
            return

    except Exception as err:
        print(f"Failed to install kube-bench on {node_ip}: {err}")
    finally:
        client.close()


def create_exempt_file():
    try:
        with open("exempt.txt", 'w') as file:
            print("Exempt file created successfully.")
            n=int(input('Enter number of controls to exempt:'))
            for i in range(0,n):
                control=input("Enter the control number:")
                file.write(control+'\n')
            
    except Exception as e:
        print(f"Error creating the file: {e}")
        return None





if __name__ == "__main__":

    if sys.argv[1]=="--exempt":
        create_exempt_file()
        quit()   



    
    
    if validate_cluster():
        node_ips = retrieve_node_ips()
        node_ips = list(OrderedDict.fromkeys(node_ips))
        master_ip=node_ips[0]
        del node_ips[0]
        ssh_username = input("Enter username of Kubenetes Cluster Nodes:")
        ssh_key_file = input("Enter key name to ssh into Cluster Nodes:")
        for node_ip in node_ips:
            if sys.argv[1]=="--include-all":
                install_kube_bench_worker_all(node_ip, ssh_username, ssh_key_file)

            else:
                install_kube_bench_worker(node_ip, ssh_username, ssh_key_file)
        if sys.argv[1]=="--include-all":
            install_kube_bench_master_all(master_ip, ssh_username, ssh_key_file)
        else:
            install_kube_bench_master(master_ip, ssh_username, ssh_key_file)
    else:       
        print("Cluster is Rebooting (Wait till available) ")
