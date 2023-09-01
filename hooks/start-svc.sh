printenv

cd /tmp
mkdir cache
mkdir cache/datarecipients

cp /tmp/docker-cache/datarecipients/* /tmp/cache/datarecipients/

java -jar -Dserver.port=8084 app.war
