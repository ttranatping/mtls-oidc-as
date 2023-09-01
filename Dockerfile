# Maven build container
  
FROM maven:3.6.3-openjdk-11-slim AS maven_build

WORKDIR /tmp/

COPY pom.xml /tmp/
#RUN mvn dependency:go-offline

COPY src /tmp/src/

RUN mvn package

#pull base image

FROM eclipse-temurin:11.0.18_10-jre-jammy

COPY hooks /tmp/hooks/
COPY wait-for /tmp/

#RUN apk --no-cache --update add git

# resolving CVE-2019-14697
#RUN apk upgrade musl

#maintainer
MAINTAINER ttran@pingidentity.com
#expose port 8080
EXPOSE 8084

CMD cd /tmp/ && ./hooks/start-svc.sh

COPY docker-cache /tmp/docker-cache

COPY --from=maven_build /tmp/target/cdr-register-testharness-0.0.1-SNAPSHOT.war /tmp/app.war
