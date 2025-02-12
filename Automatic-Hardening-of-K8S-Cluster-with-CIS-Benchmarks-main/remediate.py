import subprocess
import paramiko


def cis_1_1_1(client,remediated_controls):
    run_command="sudo chmod 600 /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.1.1  API server pod specification file permissions are set to 600")


def cis_1_1_2(client,remediated_controls):
    run_command="sudo chown root:root /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.1.2  API server pod specification file ownership is set to root:root")    


def cis_1_1_3(client,remediated_controls):
    run_command="sudo chmod 600 /etc/kubernetes/manifests/kube-controller-manager.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.1.3  Controller Manager pod specification file permissions are set to 600")    


def cis_1_1_4(client,remediated_controls):
    run_command="sudo chown root:root /etc/kubernetes/manifests/kube-controller-manager.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.1.4  Controller Manager pod specification file ownership is set to root:root")


def cis_1_1_5(client,remediated_controls):
    run_command="sudo chmod 600 /etc/kubernetes/manifests/kube-scheduler.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.1.5  Scheduler pod specification file permissions are set to 600")


def cis_1_1_6(client,remediated_controls):
    run_command="sudo chown root:root /etc/kubernetes/manifests/kube-scheduler.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.1.6  Scheduler pod specification file ownership is set to root:root")


def cis_1_1_7(client,remediated_controls):
    remediated_controls.append("1.1.7  No etcd file used because s3 bucket is used as statefile which is secure.")


def cis_1_1_8(client,remediated_controls):
    remediated_controls.append("1.1.8  No etcd file used because s3 bucket is used as statefile which is secure.")    

def cis_1_1_9(print_manual_benchmarks):
    print_manual_benchmarks.append("1.1.9  Run command based on location - chmod 600 <path/to/cni/files>")

def cis_1_1_10(print_manual_benchmarks):
    print_manual_benchmarks.append("1.1.10  Run command based on location - chown root:root <path/to/cni/files>")

def cis_1_1_11(client,remediated_controls):
    remediated_controls.append("1.1.11  No etcd file used because s3 bucket is used as statefile which is secure.")


def cis_1_1_12(client,remediated_controls):
    remediated_controls.append("1.1.12  No etcd file used because s3 bucket is used as statefile which is secure.")


def cis_1_1_13(client,remediated_controls):
    remediated_controls.append("1.1.13  This file contents are already secured in control 1.1.1 and 1.1.2.")


def cis_1_1_14(client,remediated_controls):
    remediated_controls.append("1.1.14  This file contents are already secured in control 1.1.1 and 1.1.2.")


def cis_1_1_15(client,remediated_controls):
    remediated_controls.append("1.1.15  This file contents are already secured in control 1.1.5 and 1.1.6")


def cis_1_1_16(client,remediated_controls):
    remediated_controls.append("1.1.16  This file contents are already secured in control 1.1.5 and 1.1.6")


def cis_1_1_17(client,remediated_controls):
    remediated_controls.append("1.1.17  This file contents are already secured in control 1.1.3 and 1.1.4")


def cis_1_1_18(client,remediated_controls):
    remediated_controls.append("1.1.18  This file contents are already secured in control 1.1.3 and 1.1.4")


def cis_1_1_19(client,remediated_controls):
    run_command="sudo chown -R root:root /etc/kubernetes/pki/"
    client.exec_command(run_command)
    remediated_controls.append("1.1.19  Kubernetes PKI directory and file ownership is set to root:root")    

def cis_1_1_20(print_manual_benchmarks):
    print_manual_benchmarks.append("1.1.20  Run command based on location - chmod 600 etc/kubernetes/pki/*.crt")

def cis_1_1_21(print_manual_benchmarks):
    print_manual_benchmarks.append("1.1.21  Run command based on location - chmod -R 600 etc/kubernetes/pki/*.key")

def cis_1_2_1(print_manual_benchmarks):
    print_manual_benchmarks.append("1.2.1   Set --anonymous-auth=false on the API Server pod specification file")

def cis_1_2_2(client,remediated_controls):
    run_command="sudo sed -i '/--token-auth-file=/d' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.2   Ensuring the --token-auth-file parameter is not set") 

def cis_1_2_3(print_manual_benchmarks):
    print_manual_benchmarks.append("1.2.3   Remove Deny Service External IPs parameter on API server pod specification file")

def cis_1_2_4(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --kubelet-https=true' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.4   Kubelet https argument is set to true")  


def cis_1_2_5(client,remediated_controls):
    run_command=["sudo sed -i '/args:/a \ \ \ \ - --kubelet-client-certificate=/srv/kubernetes/kube-apiserver/kubelet-api.crt' /etc/kubernetes/manifests/kube-apiserver.manifest",
                 "sudo sed -i '/args:/a \ \ \ \ - --kubelet-client-key=/srv/kubernetes/kube-apiserver/kubelet-api.key' /etc/kubernetes/manifests/kube-apiserver.manifest"]
    client.exec_command(run_command[0])
    client.exec_command(run_command[1])
    remediated_controls.append("1.2.5   Kubelet client certificate and client key arguments are set as appropriate")


def cis_1_2_6(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --kubelet-certificate-authority=/srv/kubernetes/ca.crt' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.6   Kubelet certificate authority argument is set as appropriate")  


def cis_1_2_7(client,remediated_controls):
    run_command="sudo sed -i '/--authorization-mode=AlwaysAllow/d' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.7   Authorization-mode argument is not set to AlwaysAllow") 


def cis_1_2_8(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --authorization-mode=Node' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.8   Authorization-mode argument includes Node")   


def cis_1_2_9(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --authorization-mode=RBAC' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.9   Authorization-Mode argument includes RBAC")      

def cis_1_2_10(print_manual_benchmarks):
    print_manual_benchmarks.append("1.2.10  Set --enable-admission-plugins=...,EventRateLimit,... on API server pod specification file")
    print_manual_benchmarks.append("1.2.10  Set --admission-control-config-file=<path/to/configuration/file>")


def cis_1_2_11(client,remediated_controls):
    run_command="sudo sed -i '/--enable-admission-plugins=AlwaysAdmit/d' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.11  Ensuring the admission control plugin AlwaysAdmit is not set")  

def cis_1_2_12(print_manual_benchmarks):
    print_manual_benchmarks.append("1.2.12  Set --disable-admission-plugins=...,AlwaysPullImages,... on API server pod specification file")

def cis_1_2_13(print_manual_benchmarks):
    print_manual_benchmarks.append("1.2.13  Set --disable-admission-plugins=...,SecurityContextDeny,... on API server pod specification file")


def cis_1_2_14(client,remediated_controls):
    run_command="sudo sed -i '/--disable-admission-plugins=ServiceAccount/d' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.14  Ensuring the admission control plugin ServiceAccount is set") 


def cis_1_2_15(client,remediated_controls):
    run_command="sudo sed -i '/--disable-admission-plugins=NamespaceLifecycle/d' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.15  Ensuring the admission control plugin NamespaceLifecycle is set")


def cis_1_2_16(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --enable-admission-plugins=NodeRestriction' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.16  Ensuring the admission control plugin NodeRestriction is set")


def cis_1_2_17(client,remediated_controls):
    run_command="sudo sed -i '/--secure-port=0/d' /etc/kubernetes/mainfests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.17  Ensuring the --secure-port argument is not set to 0")


def cis_1_2_18(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --profiling=false' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.18  Ensuring that the --profiling argument is set to false")


def cis_1_2_19(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --audit-log-path=/var/log/apiserver/audit.log' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.19  Audit Log Path argument is set")


def cis_1_2_20(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --audit-log-maxage=30' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.20  Audit Log Maxage Argument is set to 30")


def cis_1_2_21(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --audit-log-maxbackup=10' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.21  Audit Log Max Backup is set to 10")


def cis_1_2_22(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --audit-log-maxsize=100' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.22  Audit Log Max Size is set to 100")           

def cis_1_2_23(print_manual_benchmarks):
    print_manual_benchmarks.append("1.2.23  Set --request-timeout=300s on API server pod specification file </etc/kubernetes/manifests/kubeapiserver.yaml>")

def cis_1_2_24(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --service-account-lookup=true' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.24  Service Account Lookup is set to true")   


def cis_1_2_25(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --service-account-key-file=/srv/kubernetes/kube-apiserver/service-account.pub' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.25  Service Account Key File is set as appropriate") 


def cis_1_2_26(client,remediated_controls):
    run_command=["sudo sed -i '/args:/a \ \ \ \ - --etcd-certfile=/srv/kubernetes/kube-apiserver/etcd-client.crt' /etc/kubernetes/manifests/kube-apiserver.manifest",
                 "sudo sed -i '/args:/a \ \ \ \ - --etcd-keyfile=/srv/kubernetes/kube-apiserver/etcd-client.key' /etc/kubernetes/manifests/kube-apiserver.manifest"]
    client.exec_command(run_command[0])
    client.exec_command(run_command[1])
    remediated_controls.append("1.2.26  Etcd Certfile and Keyfile arguments are set as appropriate") 


def cis_1_2_27(client,remediated_controls):       
    run_command=["sudo sed -i '/args:/a \ \ \ \ - --tls-cert-file=/srv/kubernetes/kube-apiserver/server.crt' /etc/kubernetes/manifests/kube-apiserver.manifest",
                 "sudo sed -i '/args:/a \ \ \ \ - --tls-private-key-file=/srv/kubernetes/kube-apiserver/server.key' /etc/kubernetes/manifests/kube-apiserver.manifest"]
    client.exec_command(run_command[0])
    client.exec_command(run_command[1])
    remediated_controls.append("1.2.27  TLS Certfile and Keyfile arguments are set as appropriate") 


def cis_1_2_28(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --client-ca-file=/srv/kubernetes/ca.crt' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.28  Client CA File is set as appropriate") 


def cis_1_2_29(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --etcd-cafile=/srv/kubernetes/kube-apiserver/etcd-ca.crt' /etc/kubernetes/manifests/kube-apiserver.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.2.29  Etcd CA File argument is set as appropriate") 

def cis_1_2_30(print_manual_benchmarks):
    print_manual_benchmarks.append("1.2.30  Set --encryption-provider-config=<path/to/encryption-config-file> on API server pod specification file")

def cis_1_2_31(print_manual_benchmarks):
    print_manual_benchmarks.append("1.2.31  Configure EncryptionConfig file and Choose appropriate encryption provider")

def cis_1_2_32(print_manual_benchmarks):
    print_manual_benchmarks.append("1.2.32  Set --tls-cipher parameter on API server pod specification file")

def cis_1_3_1(print_manual_benchmarks):
    print_manual_benchmarks.append("1.3.1   Set --terminated-pod-gcthreshold to an appropriate threshold on Controller Manager pod specification file")

def cis_1_3_2(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --profiling=false' /etc/kubernetes/manifests/kube-controller-manager.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.3.2   Profiling argument is set to false")


def cis_1_3_3(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --use-service-account-credentials=true' /etc/kubernetes/manifests/kube-controller-manager.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.3.3   Use Service Account Credentials argument is set to true")


def cis_1_3_4(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --service-account-private-key-file=/srv/kubernetes/kube-controller-manager/service-account.key' /etc/kubernetes/manifests/kube-controller-manager.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.3.4   Service Account Private Key File argument is set as appropriate")


def cis_1_3_5(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --root-ca-file=/srv/kubernetes/ca.crt' /etc/kubernetes/manifests/kube-controller-manager.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.3.5   Root CA File argument is set as appropriate")


def cis_1_3_6(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --feature-gates=RotateKubeletServerCertificate=true' /etc/kubernetes/manifests/kube-controller-manager.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.3.6   Rotate Kubelet Server Certificate argument is set to true")


def cis_1_3_7(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --bind-address=127.0.0.1' /etc/kubernetes/manifests/kube-controller-manager.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.3.7   Bind Address argument is set to 127.0.0.1")


def cis_2_1(client,remediated_controls):
    remediated_controls.append("2.1     These arguements are already secured because statefile is stored in S3 bucket.")    


def cis_1_4_1(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --profiling=false' /etc/kubernetes/manifests/kube-scheduler.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.4.1   Profiling argument is set to false")

def cis_2_7(print_manual_benchmarks):
    print_manual_benchmarks.append("2.7     Set --trusted-ca-file=</path/to/ca-file> on etcd pod specification file")

def cis_3_1_1(print_manual_benchmarks):
    print_manual_benchmarks.append("3.1.1   Use of OIDC should be implemented in place of client certificates.")

def cis_3_1_2(print_manual_benchmarks):
    print_manual_benchmarks.append("3.1.2   Use of OIDC should be implemented in place of service account tokens.")

def cis_3_1_3(print_manual_benchmarks):
    print_manual_benchmarks.append("3.1.3   Use of OIDC should be implemented in place of bootstrap tokens.")

def cis_3_2_1(print_manual_benchmarks):
    print_manual_benchmarks.append("3.2.1   Create an audit policy file for your cluster.")

def cis_3_2_2(print_manual_benchmarks):
    print_manual_benchmarks.append("3.2.2   Modification of the audit policy in use on the cluster to include these items, at a minimum")

def cis_1_4_2(client,remediated_controls):
    run_command="sudo sed -i '/args:/a \ \ \ \ - --bind-address=127.0.0.1' /etc/kubernetes/manifests/kube-scheduler.manifest"
    client.exec_command(run_command)
    remediated_controls.append("1.4.2   Bind Address argument is set to 127.0.0.1")


def cis_4_1_1(client,remediated_controls):
    run_command="sudo chmod 600 /lib/systemd/system/kubelet.service"
    client.exec_command(run_command)
    remediated_controls.append("4.1.1   Kubelet Service file permissions are set to 600")


def cis_4_1_2(client,remediated_controls):
    run_command="sudo chown root:root /lib/systemd/system/kubelet.service"
    client.exec_command(run_command)
    remediated_controls.append("4.1.2   Kubelet Service file ownership is set to root:root")

def cis_4_1_3(print_manual_benchmarks):
    print_manual_benchmarks.append("4.1.3   Run command based on location - chmod 600 <proxy kubeconfig file>")

def cis_4_1_4(print_manual_benchmarks):
    print_manual_benchmarks.append("4.1.4   Run command based on location - chown root:root <proxy kubeconfig file>")

def cis_4_1_5(client,remediated_controls):
    run_command="sudo chmod 600 /var/lib/kubelet/kubelet.conf"
    client.exec_command(run_command)
    remediated_controls.append("4.1.5   Kubelet Configuration file permissions are set to 600")


def cis_4_1_6(client,remediated_controls):
    run_command="sudo chown root:root /var/lib/kubelet/kubelet.conf"
    client.exec_command(run_command)
    remediated_controls.append("4.1.6   Kubelet Configuration file ownership is set to root:root")

def cis_4_1_7(print_manual_benchmarks):
    print_manual_benchmarks.append("4.1.7   Modify file permissions of --client-ca-file <chmod 600 <filename>>")

def cis_4_1_9(client,remediated_controls):
    run_command="sudo chmod 600 /var/lib/kubelet/kubeconfig"
    client.exec_command(run_command)
    remediated_controls.append("4.1.9   Kubelet Kubeconfig file permissions are set to 600")

def cis_4_1_8(print_manual_benchmarks):
    print_manual_benchmarks.append("4.1.8   Modify ownership of --client-ca-file <chown root:root <filename>>")


def cis_4_1_10(client,remediated_controls):
    run_command="sudo chown root:root /var/lib/kubelet/kubeconfig"
    client.exec_command(run_command)
    remediated_controls.append("4.1.10  Kubelet Kubeconfig file ownership is set to root:root")


def cis_4_2_1(client,remediated_controls):
    run_command=["sudo sed -i '8s/.*/& --anonymous-auth=false/' /lib/systemd/system/kubelet.service",
                 "sudo systemctl daemon-reload","sudo systemctl restart kubelet.service"]
    client.exec_command(run_command[0])
    client.exec_command(run_command[1])
    remediated_controls.append("4.2.1   Anonymous Authentication is set to False")


def cis_4_2_2(client,remediated_controls):
    run_command=["sudo sed -i '8s/.*/& --authorization-mode=Webhook/' /lib/systemd/system/kubelet.service",
                 "sudo systemctl daemon-reload","sudo systemctl restart kubelet.service"]

    client.exec_command(run_command[0])
    client.exec_command(run_command[1])
    remediated_controls.append("4.2.2   Authorization Mode is not set to AlwaysAllow")


def cis_4_2_3(client,remediated_controls):
    run_command=["sudo sed -i '8s/.*/& --client-ca-file=/srv/kubernetes/ca.crt/' /lib/systemd/system/kubelet.service",
                 "sudo systemctl daemon-reload","sudo systemctl restart kubelet.service"]

    client.exec_command(run_command[0])
    client.exec_command(run_command[1])
    remediated_controls.append("4.2.3   Client CA File is set as apporpriate")

def cis_4_2_4(print_manual_benchmarks):
    print_manual_benchmarks.append("4.2.4   Set --read-only-port=0 on kubelet service file")

def cis_4_2_5(print_manual_benchmarks):
    print_manual_benchmarks.append("4.2.5   Set --streaming-connection-idle-timeout=5m on kubelet service file")

def cis_4_2_6(client,remediated_controls):
    run_command=["sudo sed -i '8s/.*/& --protect-kernel-defaults=true/' /lib/systemd/system/kubelet.service",
                 "sudo systemctl daemon-reload","sudo systemctl restart kubelet.service"]

    client.exec_command(run_command[0])
    client.exec_command(run_command[1])
    remediated_controls.append("4.2.6   Protect Kernel Defaults is set to True")     


def cis_4_2_7(client,remediated_controls):
    run_command=["sudo sed -i '8s/.*/& --make-iptables-util-chains=true/' /lib/systemd/system/kubelet.service",
                 "sudo systemctl daemon-reload","sudo systemctl restart kubelet.service"]

    client.exec_command(run_command[0])
    client.exec_command(run_command[1])
    remediated_controls.append("4.2.7   Make Iptables Util Chains is set to True")    

def cis_4_2_8(print_manual_benchmarks):
    print_manual_benchmarks.append("4.2.8   Set eventRecordQPS to an appropriate level on kubelet config file")

def cis_4_2_9(print_manual_benchmarks):
    print_manual_benchmarks.append("4.2.9   Set tlsCertFile and tlsPrivateKeyFile as appropriate on kubelet config file")

def cis_4_2_10(print_manual_benchmarks):
    print_manual_benchmarks.append("4.2.10  Set rotateCertificates to true on kubelet service file")

def cis_4_2_11(client,remediated_controls):
    run_command=["sudo sed -i 's/--rotate-certificates=false//g' /lib/systemd/system/kubelet.service",
                 "sudo systemctl daemon-reload","sudo systemctl restart kubelet.service"]

    client.exec_command(run_command[0])
    client.exec_command(run_command[1])
    remediated_controls.append("4.2.11  Rotate Certificates is not set to False")

def cis_4_2_12(print_manual_benchmarks):
    print_manual_benchmarks.append("4.2.12  Set --feature-gates=RotateKubeletServerCertificate=true on kubelet service file")

def cis_4_2_13(print_manual_benchmarks):
    print_manual_benchmarks.append("4.2.13  Set --tls-cipher-suites parameter on kubelet service file")

def cis_5_1_1(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.1   Bind users to a lower privileged role and then remove the clusterrolebinding to the cluster-admin role")

def cis_5_1_2(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.2   Remove get, list and watch access to secret objects in the cluster.")

def cis_5_1_3(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.3   Replace any use of wildcards in clusterroles and roles with specific objects or actions.")

def cis_5_1_4(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.4   Remove create access to pod objects in the cluster")

def cis_5_1_5(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.5   Include automountServiceAccountToken: false on each default service account ")

def cis_5_1_6(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.6   Disable unnecessary service account token mounting in pod and service account definition")

def cis_5_1_7(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.7   Remove the system:masters group from all users in the cluster")

def cis_5_1_8(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.8   Remove the impersonate, bind and escalate rights from subjects where possible")

def cis_5_1_9(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.9   Remove create access to PersistentVolume objects in the cluster where possible")

def cis_5_1_10(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.10  Remove access to the proxy sub-resource of node objects where possible")

def cis_5_1_11(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.11  Remove access to the approval sub-resource of certificatesigningrequest objects where possible")

def cis_5_1_12(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.12  Remove access to the validatingwebhookconfigurations or mutatingwebhookconfigurations objects")

def cis_5_1_13(print_manual_benchmarks):
    print_manual_benchmarks.append("5.1.13  Remove access to the token sub-resource of serviceaccount objects.")

def cis_5_2_1(print_manual_benchmarks):
    print_manual_benchmarks.append("5.2.1   Ensure Pod Security Admission or external policy control for user workloads in every namespace.")

def cis_5_2_2(print_manual_benchmarks):
    print_manual_benchmarks.append("5.2.2   Apply policies to limit admission of privileged containers in namespaces with user workloads.")

def cis_5_2_3(client,remediated_controls):
    run_command="kubectl apply -f 5_2_3.yaml"       
    subprocess.run(run_command)
    remediated_controls.append("5.2.3   Minimized the admission of containers wishing to share the host process ID namespace")

def cis_5_2_4(client,remediated_controls):
    run_command="kubectl apply -f 5_2_4.yaml"       
    subprocess.run(run_command)
    remediated_controls.append("5.2.4   Minimized the admission of containers wishing to share the host IPC namespace")

def cis_5_2_5(client,remediated_controls):
    run_command="kubectl apply -f 5_2_5.yaml"            
    subprocess.run(run_command)
    remediated_controls.append("5.2.5   Minimized the admission of containers wishing to share the host network namespace")

def cis_5_2_6(client,remediated_controls):
    run_command="kubectl apply -f 5_2_6.yaml"        
    subprocess.run(run_command)
    remediated_controls.append("5.2.6   Minimized the admission of containers with allowPrivilegeEscalation")


"""def cis_5_2_6(client,remediated_controls):
    run_command="kubectl apply -f 5_2_6.yaml"
    subprocess.run(run_command)
    remediated_controls.append("")"""


def cis_5_2_7(client,remediated_controls):
    run_command="kubectl apply -f 5_2_7.yaml"        
    subprocess.run(run_command)
    remediated_controls.append("5.2.7   Minimized the admission of root containers")    


def cis_5_2_8(client,remediated_controls):
    run_command="kubectl apply -f 5_2_8.yaml"        
    subprocess.run(run_command)
    remediated_controls.append("5.2.8   Minimized the admission of containers with the NET_RAW capability")


def cis_5_2_9(client,remediated_controls):
    run_command="kubectl apply -f 5_2_9.yaml"     
    subprocess.run(run_command)
    remediated_controls.append("5.2.9   Minimized the admission of containers with added capabilities")

def cis_5_2_10(print_manual_benchmarks):
    print_manual_benchmarks.append("5.2.10  Review the use of capabilities in applications running on your cluster.")

def cis_5_2_11(print_manual_benchmarks):
    print_manual_benchmarks.append("5.2.11  Apply policies to restrict the admission of hostProcess containers in namespaces with user workloads.")

def cis_5_2_12(print_manual_benchmarks):
    print_manual_benchmarks.append("5.2.12  Apply policies to restrict the admission of hostPath volumes in namespaces with user workloads.")

def cis_5_2_13(print_manual_benchmarks):
    print_manual_benchmarks.append("5.2.13  Apply policies to restrict the admission of containers using hostPort sections in namespaces with user workloads.")

def cis_5_3_1(print_manual_benchmarks):
    print_manual_benchmarks.append("5.3.1   Switch to different plugin if CNI plugin does not support network policies")

def cis_5_3_2(print_manual_benchmarks):
    print_manual_benchmarks.append("5.3.2   Create NetworkPolicy objects as you need them")

def cis_5_4_1(print_manual_benchmarks):
    print_manual_benchmarks.append("5.4.1   Rewrite application code to read secrets from mounted secret files")

def cis_5_4_2(print_manual_benchmarks):
    print_manual_benchmarks.append("5.4.2   Refer to the secrets management options offered by your cloud provider")

def cis_5_5_1(print_manual_benchmarks):
    print_manual_benchmarks.append("5.5.1   Follow the Kubernetes documentation and setup image provenance.")

def cis_5_7_1(print_manual_benchmarks):
    print_manual_benchmarks.append("5.7.1   Create namespaces for objects in your deployment as you need them")

def cis_5_7_2(print_manual_benchmarks):
    print_manual_benchmarks.append("5.7.2   Use security context to enable the docker/default seccomp profile in your pod definitions.")

def cis_5_7_3(print_manual_benchmarks):
    print_manual_benchmarks.append("5.7.3   Apply security contexts to your pods.")

def cis_5_7_4(print_manual_benchmarks):
    print_manual_benchmarks.append("5.7.4   Create namespaces to allow appropriate segregation of Kubernetes resources.")