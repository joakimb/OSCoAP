echo "building COSE as local depandency"
cp cosepom.xml COSE-JAVA/pom.xml
cd COSE-JAVA
mvn package -DskipTests
cd ..
echo "DONE"
