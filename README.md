# OIDC Authentication for Airflow Local Example Setup

1. Clone repo down to local machine, docker is required locally to run the containers/ launch the docker compose services.
2. Rename .example.env to .env, and fill in appropriate details.
3. Rename client_secret.example to client_secret.json, replace CLIENT_ID and CLIENT_SECRET with appropriate values from Gitlab IDP Application setup.
3. Build the image from the included Dockerfile, tagging it "airflow-oidc" -
```
docker build -t airflow-oidc .
```
4. Follow steps from included documentation in order to generate Client ID and Secret for a Gitlab application we will use as the auth provider, which is what is being referred to in step 2.
5. After image has finished building, you can launch the entire stack with:
```
docker-compose -f airflow-etl.yaml up
```
6. Browse to http://localhost:8060, and if setup is done correctly, you will be redirected to a Gitlab login page.  Login here, and you will be redirected to the local airflow instance.
7. Your first time logging in you will likely have a screen that says "Your user has no roles and/or permissions!", this is because the user did not previously exist in the included DB, and we need to assign them proper permissions.
8. Connect to the service labeled "openid-app-airflow-webserver-*" by entering 
```
docker ps
```
In the terminal, then copying the instance id of the container matching the label above.
Now we can enter a console on that container with:
```
docker exec -it <CONTAINER_ID> bash
```
Then we can view the list of airflow users, which will show the user that was just created after logging in with Gitlab:
```
airflow users list
```
You will see an output similar to this:
```
docker exec -it 8a47b651a82a bash
airflow@8a47b651a82a:/opt/airflow$ airflow users list
id | username     | email                    | first_name | last_name | roles
===+==============+==========================+============+===========+=============
1  | airflow      | airflowadmin@example.com | Airflow    | Admin     | Admin
2  | mark.degroat | mark.degroat@rearc.io    | Mark       | deGroat   | Admin,Public
```

Take note of the username, and in that same bash console for the container, assign permissions to that new user:
```
airflow users add-role -u <USERNAME> -r Admin
```
Which when combined with the value from the table above, becomes:
```
airflow users add-role -u mark.degroat -r Admin
```
9. Refresh the page, and you should now see the Airflow dashboard, logged in as the user shown above with Admin permissions.
