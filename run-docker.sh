#check if producttion docker exest and stop it
if [ "$(sudo docker ps -a -q -f name=mikroman)" ]; then
    if [ "$(sudo docker ps -aq -f status=running -f name=mikroman)" ]; then
        # cleanup
        echo "stoping production docker"
        sudo docker container stop mikroman
    fi
    # run your container
fi

mydir=$(pwd)
pydir="${mydir}/py"
dbmigratedir="${mydir}/migrations"
firmdir="${mydir}/firms"
backupdir="${mydir}/backups"
reloaddir="${mydir}/reload"
echo "Creating backup and firms dir in current dir"
mkdir -p $firmdir
mkdir -p $backupdir
echo $firmdir
if [ -d /opt/mikrowizard/ ]; then
  echo "running and creating mikroman dev container."
  sudo docker run --rm -it --net host --name mikroman-dev --add-host=host.docker.internal:host-gateway -v /opt/mikrowizard/:/conf/ -v $dbmigratedir:/app/migrations/ -v $pydir:/app/py -v $firmdir:/firms -v $backupdir:/backups -v $reloaddir:/app/reload mikrowizard/mikroman:latest uwsgi --ini /app/conf/uwsgi.ini:uwsgi-docker-dev --touch-reload=/app/reload
fi

