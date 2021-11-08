docker stop dev-postgres
docker rm dev-postgres
docker run --name dev-postgres -p 54320:5432 -e POSTGRES_PASSWORD=mysecretpassword -d postgres