###We are using the VCF 3.x API's here to bypass giving the entries of the host usernames and passwords at the vSphere cluster level.
###For the API to work the user needs to create in vCenter a privileged user for VCF 3.x which is a member of the 'Sddc_Secured_Access' group.
###Set the admin user password for VCF using the command: /opt/vmware/vcf/commonsvcs/scripts/auth/set-basicauth-password.sh admin <password>
###The privileged-username and privileged-password for VCF is used in the below curl command based on which we use the API in the script:

curl -k 'https://sddcmanager-a.sddc.lab/v1/credentials' -i -u 'admin:VMware123!' -X GET -H 'privileged-username: vcfapi@vsphere.local' -H 'privileged-password: VMware123!' -H 'Accept: application/json' 