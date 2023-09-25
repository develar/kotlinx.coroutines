VERSION := 1.7.3-jb.1

install:
	mvn install:install-file -DgroupId=com.intellij.platform \
      -DartifactId=kotlinx-coroutines-core-jvm \
      -Dversion=$(VERSION) \
      -Dpackaging=jar \
      -Dfile=../build/libs/kotlinx-coroutines-core-jvm-1.7.3-SNAPSHOT.jar
	mvn install:install-file -DgroupId=com.intellij.platform \
      -DartifactId=kotlinx-coroutines-core-jvm \
      -Dversion=$(VERSION) \
      -Dpackaging=java-source \
      -DgeneratePom=false \
      -Dfile=../build/libs/kotlinx-coroutines-core-jvm-1.7.3-SNAPSHOT-sources.jar

deploy: install
	mvn deploy:deploy-file -DgroupId=com.intellij.platform \
      -DartifactId=kotlinx-coroutines-core-jvm \
      -Dversion=$(VERSION) \
      -Dpackaging=jar \
      -Dfile=../build/libs/kotlinx-coroutines-core-jvm-1.7.3-SNAPSHOT.jar \
      -DrepositoryId=space-intellij-dependencies \
      -Durl=https://packages.jetbrains.team/maven/p/ij/intellij-dependencies
	mvn deploy:deploy-file -DgroupId=com.intellij.platform \
      -DartifactId=kotlinx-coroutines-core-jvm \
      -Dversion=$(VERSION) \
      -DgeneratePom=false \
      -Dpackaging=java-source \
      -Dfile=../build/libs/kotlinx-coroutines-core-jvm-1.7.3-SNAPSHOT-sources.jar \
      -DrepositoryId=space-intellij-dependencies \
      -Durl=https://packages.jetbrains.team/maven/p/ij/intellij-dependencies