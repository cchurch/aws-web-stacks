import troposphere.ec2 as ec2
from troposphere import And, Condition, Equals, If, Join, Not, Output, Parameter, Ref, Tags

from .template import template
from .vpc import public_subnet, vpc

bastion_ami = template.add_parameter(
    Parameter(
        "BastionAMI",
        Description="(Optional) Bastion or VPN server AMI in the same region as this stack.",
        Type="AWS::EC2::Image::Id",
        Default="",
    ),
    group="Bastion Server",
    label="AMI",
)

bastion_instance_type = template.add_parameter(
    Parameter(
        "BastionInstanceType",
        Description="(Optional) Instance type to use for bastion server.",
        Type="String",
        AllowedValues=[
            't3.nano',
            't3.micro',
            't3.small',
            't3.medium',
            't3.large',
            't3.xlarge',
            't3.2xlarge',
            't2.nano',
            't2.micro',
            't2.small',
            't2.medium',
            't2.large',
            't2.xlarge',
            't2.2xlarge',
            'm5.large',
            'm5.xlarge',
            'm5.2xlarge',
            'm5.4xlarge',
            'm5.12xlarge',
            'm5.24xlarge',
            'm5d.large',
            'm5d.xlarge',
            'm5d.2xlarge',
            'm5d.4xlarge',
            'm5d.12xlarge',
            'm5d.24xlarge',
            'm4.large',
            'm4.xlarge',
            'm4.2xlarge',
            'm4.4xlarge',
            'm4.10xlarge',
            'm4.16xlarge',
            'm3.medium',
            'm3.large',
            'm3.xlarge',
            'm3.2xlarge',
            'c5.large',
            'c5.xlarge',
            'c5.2xlarge',
            'c5.4xlarge',
            'c5.9xlarge',
            'c5.18xlarge',
            'c5d.large',
            'c5d.xlarge',
            'c5d.2xlarge',
            'c5d.4xlarge',
            'c5d.9xlarge',
            'c5d.18xlarge',
            'c4.large',
            'c4.xlarge',
            'c4.2xlarge',
            'c4.4xlarge',
            'c4.8xlarge',
            'c3.large',
            'c3.xlarge',
            'c3.2xlarge',
            'c3.4xlarge',
            'c3.8xlarge',
            'p2.xlarge',
            'p2.8xlarge',
            'p2.16xlarge',
            'g2.2xlarge',
            'g2.8xlarge',
            'x1.16large',
            'x1.32xlarge',
            'r5.large',
            'r5.xlarge',
            'r5.2xlarge',
            'r5.4xlarge',
            'r5.12xlarge',
            'r5.24xlarge',
            'r4.large',
            'r4.xlarge',
            'r4.2xlarge',
            'r4.4xlarge',
            'r4.8xlarge',
            'r4.16xlarge',
            'r3.large',
            'r3.xlarge',
            'r3.2xlarge',
            'r3.4xlarge',
            'r3.8xlarge',
            'i3.large',
            'i3.xlarge',
            'i3.2xlarge',
            'i3.4xlarge',
            'i3.8xlarge',
            'i3.16large',
            'd2.xlarge',
            'd2.2xlarge',
            'd2.4xlarge',
            'd2.8xlarge',
            'f1.2xlarge',
            'f1.16xlarge',
        ],
        Default="t2.nano",
    ),
    group="Bastion Server",
    label="Instance Type",
)

bastion_is_pfsense = template.add_parameter(
    Parameter(
        "BastionPfSense",
        Description="Whether or not bastion is running pfSense.",
        Type="String",
        AllowedValues=[
            'true',
            'false',
        ],
        Default="false",
    ),
    group="Bastion Server",
    label="Is pfSense?",
)

bastion_key_name = template.add_parameter(
    Parameter(
        "BastionKeyName",
        Description="Name of an existing EC2 KeyPair to enable SSH access to "
                    "the Bastion instance. This parameter is required even if "
                    "no Bastion AMI is specified (but will be unused).",
        Type="AWS::EC2::KeyPair::KeyName",
        ConstraintDescription="must be the name of an existing EC2 KeyPair."
    ),
    group="Bastion Server",
    label="SSH Key Name",
)

bastion_allowed_ssh_network = template.add_parameter(
    Parameter(
        "BastionAllowedSSHNetwork",
        Description="Network in CIDR format allowed SSH access to the "
                    "bastion instance.",
        Type="String",
        # AllowedPattern="",
        Default="",
        ConstraintDescription="must be a valid CIDR range."
    ),
    group="Bastion Server",
    label="Allowed SSH Network",
)

bastion_ami_set = "BastionAMISet"
template.add_condition(bastion_ami_set, Not(Equals("", Ref(bastion_ami))))

bastion_is_pfsense_set = "BastionIsPfSenseSet"
template.add_condition(bastion_is_pfsense_set, Equals("true", Ref(bastion_is_pfsense)))

bastion_allowed_ssh_network_set = "BastionAllowedSSHNetworkSet"
template.add_condition(bastion_allowed_ssh_network_set, Not(Equals("", Ref(bastion_allowed_ssh_network))))

bastion_security_group = ec2.SecurityGroup(
    'BastionSecurityGroup',
    template=template,
    GroupDescription="Bastion security group.",
    VpcId=Ref(vpc),
    Condition=bastion_ami_set,
)

bastion_security_group_ingress_ssh = ec2.SecurityGroupIngress(
    'BastionSecurityGroupIngressSSH',
    template=template,
    GroupId=Ref(bastion_security_group),
    IpProtocol="tcp",
    FromPort=22,
    ToPort=22,
    CidrIp=Ref(bastion_allowed_ssh_network),
    Condition=bastion_allowed_ssh_network_set,
)

bastion_security_group_ingress_https = ec2.SecurityGroupIngress(
    'BastionSecurityGroupIngressHTTPS',
    template=template,
    GroupId=Ref(bastion_security_group),
    IpProtocol="tcp",
    FromPort=443,
    ToPort=443,
    CidrIp=Ref(bastion_allowed_ssh_network),
    Condition=bastion_allowed_ssh_network_set,
)

bastion_security_group_ingress_openvpn = ec2.SecurityGroupIngress(
    'BastionSecurityGroupIngressOpenVPN',
    template=template,
    GroupId=Ref(bastion_security_group),
    IpProtocol="udp",
    FromPort=1194,
    ToPort=1194,
    CidrIp="0.0.0.0/0",
    Condition=bastion_is_pfsense_set,
)

# Elastic IP for Bastion instance
bastion_eip = ec2.EIP(
    "BastionEIP",
    template=template,
    Condition=bastion_ami_set,
)

bastion_instance = ec2.Instance(
    "BastionInstance",
    template=template,
    ImageId=Ref(bastion_ami),
    InstanceType=Ref(bastion_instance_type),
    KeyName=If(bastion_ami_set, Ref(bastion_key_name), Ref("AWS::NoValue")),
    SecurityGroupIds=[Ref(bastion_security_group)],
    SubnetId=Ref(public_subnet),
    Condition=bastion_ami_set,
    Tags=Tags(
        Name=Join("-", [Ref("AWS::StackName"), "bastion"]),
    ),
)

# Associate the Elastic IP separately, so it doesn't change when the instance changes.
eip_assoc = ec2.EIPAssociation(
    "BastionEIPAssociation",
    template=template,
    InstanceId=Ref(bastion_instance),
    EIP=Ref(bastion_eip),
    Condition=bastion_ami_set,
)

template.add_output([
    Output(
        "BastionIP",
        Description="Public IP address of Bastion instance",
        Value=Ref(bastion_eip),
        Condition=bastion_ami_set,
    ),
])

# Allow bastion full access to workers.
container_security_group_bastion_ingress = ec2.SecurityGroupIngress(
    'ContainerSecurityGroupBastionIngress',
    template=template,
    GroupId=Ref("ContainerSecurityGroup"),
    IpProtocol='-1',
    SourceSecurityGroupId=Ref(bastion_security_group),
    Condition=bastion_ami_set,
)

bastion_database_condition = "BastionDatabaseCondition"
template.add_condition(bastion_database_condition, And(Condition(bastion_ami_set), Condition("DatabaseCondition")))

# Allow bastion full access to database.
database_security_group_bastion_ingress = ec2.SecurityGroupIngress(
    'DatabaseSecurityGroupBastionIngress',
    template=template,
    GroupId=Ref("DatabaseSecurityGroup"),
    IpProtocol='-1',
    SourceSecurityGroupId=Ref(bastion_security_group),
    Condition=bastion_database_condition,
)
