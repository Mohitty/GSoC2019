# Project Name
Bring Your Own Application

## Student Info
* <b>Name</b> : Mohit Tyagi
* <b>University</b> : Indian Institute of Technology, Kanpur, India.
* <b>Email</b> : [mohit2501tyagi@gmail.com](mailto:mohit2501tyagi@gmail.com)
* <b>Github</b> : [github.com/Mohitty](https://github.com/Mohitty)

### [GSoC Project Page](https://summerofcode.withgoogle.com/projects/#4701513761423360)

### Work Summary
For GSoC 2019 I created the following two Phoenix application:
#### User Preferences App
The user preferences will be used to associate mime types with application providers. These associations are used to determine the application to be used to open the corresponding file. The following repository contains the source code for the app: https://github.com/Mohitty/SettingsApp

#### A Reference Collaborative app
For this I created a Root Viewer app. I integrated https://root.cern.ch/js/ to reva and created a Phoenix app to use the corresponding REVA service. The following repository contains the source code for the app: https://github.com/Mohitty/RootViewer

### What is covered
All the proposed milestones are successfully completed.
- [x] M1.1 Design in protobuf and gRPC the Settings API
- [x] M1.2 Implementation of Settings API in REVA
- [x] M1.3 Implementation Settings API in REVA clients

- [x] M2.1 Create js library to use the Settings API
- [x] M2.2 Create a Phoenix app to display settings for a user
- [x] M2.3 Modify Phoenix app to modify user settings
  
- [x] M3.1 Create a CS3 application provider
- [x] M3.2 Create a Phoenix app to load the iframe obtained from CS3 API

The following pull requests covers the work done in REVA:
- https://github.com/cs3org/reva/pull/204
- https://github.com/cs3org/reva/pull/178
- https://github.com/cs3org/reva/pull/177
- https://github.com/cs3org/reva/pull/176
- https://github.com/cs3org/reva/pull/157
- https://github.com/cs3org/reva/pull/154
- https://github.com/cs3org/reva/pull/104
- https://github.com/cs3org/reva/pull/100
- https://github.com/cs3org/go-cs3apis/pull/3
- https://github.com/cs3org/cs3apis/pull/11
- https://github.com/cs3org/reva/pull/91
- https://github.com/cs3org/reva/pull/88

The following two repositories contains the work done in Phoenix:
- https://github.com/Mohitty/SettingsApp
- https://github.com/Mohitty/RootViewer

To run the apps follow these steps:
- Getting up phoenix:
  1. Clone the owncloud Phoenix repository: https://github.com/owncloud/phoenix
  2. Put the two Phoenix apps mentioned above in the apps directory of Phoenix repo.
  3. Save the following config file as config.json in the root of Phoenix directory
  ```{
  "server" : "http://localhost:9998",
  "theme": "owncloud",
  "version": "0.1.0",
  "openIdConnect": {
    "authority": "http://localhost:9998",
    "metadataUrl": "http://localhost:9998/.well-known/openid-configuration",
    "client_id": "phoenix",
    "client_secret": "foobar",
    "response_type": "code",
    "scope": "openid profile email",
    "extraQueryParams": {
      "claims": "{\"userinfo\":{\"name\":{\"essential\":true},\"preferred_username\":{\"essential\":true},\"email\":{\"essential\":true},\"email_verified\":{\"essential\":true},\"picture\":null}}"
    }
  },
  "apps" : [
    "files", "markdown-editor", "pdf-viewer", "preferences", "root-viewer"
  ]
  ```
  4. (Alternative Step) Instead of above three steps you can use my local repo with all the above steps already done: https://github.com/Mohitty/preferencesApp . Then go to the next step.
  5. Run the following commands in order, from the root of the repo:
    - `yarn install`
    - `yarn dist`
    - `docker run --rm -it --name node-docker -v $PWD:/home/app -w /home/app -e "PORT=3000" -p 3000:3000 -p 8300:8300  -u node node:latest yarn watch`
  
- Getting up REVA:
  1. Clone the reva repository: https://github.com/cs3org/reva
  2. Save the following config file as local.toml in the root of reva repo:
  ```
  [core]
  max_cpus = "2"

  [log]
  output = "stdout"
  mode = "dev"
  level = "debug"

  [http]
  enabled_services = ["appregistrysvc", "datasvc", "ocdavsvc", "ocssvc", "oidcprovider", "wellknown","preferencessvc", "iframeuisvc"]
  #enabled_middlewares = ["log", "trace", "auth", "cors"]
  enabled_middlewares = ["log", "trace", "auth", "cors"]
  network = "tcp"
  address = "0.0.0.0:9998"

  [http.middlewares.trace]
  priority = 100
  header = "x-trace"

  [http.middlewares.log]
  priority = 200

  [http.middlewares.auth]
  priority = 300
  authsvc = "127.0.0.1:9999"
  credential_strategy = "oidc"
  #credential_strategy = "basic"
  token_strategy = "header"
  token_writer = "header"
  token_manager = "jwt"
  skip_methods = [
      "/status.php",
      "/oauth2",
      "/oauth2/auth", 
      "/oauth2/token", 
      "/oauth2/introspect",
      "/oauth2/userinfo", 
      "/oauth2/sessions", 
      "/.well-known/openid-configuration",
      "/data"
  ]

  [http.middlewares.cors]
  priority = 400
  allowed_origins = ["*"]
  allow_credentials = true
  allowed_methods = ["OPTIONS", "GET", "PUT", "POST", "DELETE", "MKCOL", "PROPFIND", "PROPPATCH", "MOVE", "COPY", "REPORT", "SEARCH"]
  allowed_headers = ["Origin", "Accept", "Content-Type", "X-Requested-With", "Authorization", "Ocs-Apirequest"]
  options_passthrough = true

  [http.middlewares.auth.token_managers.jwt]
  secret = "Pive-Fumkiu4"

  [http.middlewares.auth.token_strategies.header]
  header = "X-Access-Token"

  [http.middlewares.auth.token_writers.header]
  header = "X-Access-Token"

  [http.services.appregistrysvc]
  prefix = "appregistry"
  gatewaysvc = "localhost:9999"

  [http.services.preferencessvc]
  prefix = "preferences"
  preferencessvc = "localhost:9999"

  [http.services.iframeuisvc]
  prefix = "iframe"

  [http.services.ocdavsvc]
  prefix = ""
  chunk_folder = "/var/tmp/owncloud/chunks"
  storageregistrysvc = "127.0.0.1:9999"
  storageprovidersvc = "127.0.0.1:9999"
  enable_cors = true

  [http.services.ocssvc]
  prefix = "ocs"
  publicshareprovidersvc = "" # "" = disabled
  usershareprovidersvc = "127.0.0.1:9999"
  storageprovidersvc = "127.0.0.1:9999"
  user_manager = "oidc"

  [http.services.ocssvc.user_managers.json]
  users = "users.json"

  [http.services.ocssvc.config]
  version = "1.8"
  website = "nexus"
  host = "https://localhost:9998"
  contact = "admin@localhost"
  ssl = "true"
  [http.services.ocssvc.capabilities.capabilities.core]
  poll_interval = 60
  webdav_root = "remote.php/webdav"
  [http.services.ocssvc.capabilities.capabilities.core.status]
  installed = true
  maintenance = false
  needsDbUpgrade = false
  version = "10.0.9.5"
  versionstring = "10.0.9"
  edition = "community"
  productname = "reva"
  hostname = ""
  [http.services.ocssvc.capabilities.capabilities.checksums]
  supported_types = ["SHA256"]
  preferred_upload_type = "SHA256"
  [http.services.ocssvc.capabilities.capabilities.files]
  private_links = true
  bigfilechunking = true
  blacklisted_files = ["foo"]
  undelete = true
  versioning = true
  [http.services.ocssvc.capabilities.capabilities.dav]
  chunking = "1.0"
  [http.services.ocssvc.capabilities.capabilities.files_sharing]
  api_enabled = true
  resharing = true
  group_sharing = true
  auto_accept_share = true
  share_with_group_members_only = true
  share_with_membership_groups_only = true
  default_permissions = 22
  search_min_length = 3
  [http.services.ocssvc.capabilities.capabilities.files_sharing.public]
  enabled = true
  send_mail = true
  social_share = true
  upload = true
  multiple = true
  supports_upload_only = true
  [http.services.ocssvc.capabilities.capabilities.files_sharing.public.password]
  enforced = true
  [http.services.ocssvc.capabilities.capabilities.files_sharing.public.password.enforced_for]
  read_only = true
  read_write = true
  upload_only = true
  [http.services.ocssvc.capabilities.capabilities.files_sharing.public.expire_date]
  enabled = true
  [http.services.ocssvc.capabilities.capabilities.files_sharing.user]
  send_mail = true
  [http.services.ocssvc.capabilities.capabilities.files_sharing.user_enumeration]
  enabled = true
  group_members_only = true
  [http.services.ocssvc.capabilities.capabilities.files_sharing.federation]
  outgoing = true
  incoming = true
  [http.services.ocssvc.capabilities.capabilities.notifications]
  endpoints = ["list", "get", "delete"]
  [http.services.ocssvc.capabilities.version]
  edition = "nexus"
  major = 10
  minor = 0
  micro = 11
  string = "10.0.11"

  [http.services.datasvc]
  driver = "local"
  prefix = "data"
  temp_folder = "/var/tmp/"

  [http.services.datasvc.drivers.local]
  root = "/data"

  [http.services.datasvc.drivers.owncloud]
  datadirectory = "/data"

  [http.services.wellknown]
  prefix = ".well-known"

  [http.services.oidcprovider]
  prefix = "oauth2"

  ## authsvc part

  [grpc]
  network = "tcp"
  address = "0.0.0.0:9999"
  access_log = "stderr"
  #tls_enabled = true
  #tls_cert = "/etc/gridsecurity/host.cert"
  #tls_key = "/etc/gridsecurity/host.key"
  enabled_services = ["authsvc", "usershareprovidersvc", "storageregistrysvc", "storageprovidersvc","preferencessvc","appregistrysvc"]
  enabled_interceptors = ["auth", "prometheus", "log", "trace"]


  [grpc.interceptors.trace]
  priority = 100
  header = "x-trace"

  [grpc.interceptors.log]
  priority = 200

  [grpc.interceptors.prometheus]
  priority = 300

  [grpc.interceptors.auth]
  priority = 400
  # TODO grpc 'headers' are stored as google.golang.org/grpc/metadata ... needs better naming, this is too confusing
  # keys for grpc metadata are always lowercase, so interceptors headers need to use lowercase.
  header = "x-access-token"
  token_strategy = "header"
  token_manager = "jwt"
  # GenerateAccessToken contains the credentials in the payload. Skip auth, otherwise services cannot obtain a token.
  skip_methods = ["/cs3.authv0alpha.AuthService/GenerateAccessToken"]

  [grpc.interceptors.auth.token_strategies.header]
  header = "X-Access-Token"

  [grpc.interceptors.auth.token_managers.jwt]
  secret = "Pive-Fumkiu4"


  [grpc.services.authsvc]
  auth_manager = "oidc"
  user_manager = "oidc"
  token_manager = "jwt"

  [grpc.services.authsvc.token_managers.jwt]
  secret = "Pive-Fumkiu4"

  [grpc.services.authsvc.auth_managers.oidc]
  provider = "http://localhost:9998"
  insecure = true
  # the client credentials for the token introspection beckchannel
  client_id = "reva"
  client_secret = "foobar"

  [grpc.services.authsvc.auth_managers.json]
  users = "users.json"

  [grpc.services.authsvc.user_managers.json]
  users = "users.json"

  [grpc.services.storageregistrysvc]
  driver = "static"

  [grpc.services.storageregistrysvc.drivers.static.rules]
  "/" = "127.0.0.1:9999"
  "123e4567-e89b-12d3-a456-426655440000" = "127.0.0.1:9999"


  [grpc.services.storageprovidersvc]
  driver = "local"
  mount_path = "/"
  mount_id = "123e4567-e89b-12d3-a456-426655440000"
  data_server_url = "http://127.0.0.1:9998/data"

  [grpc.services.storageprovidersvc.available_checksums]
  md5   = 100
  unset = 1000

  [grpc.services.storageprovidersvc.drivers.local]
  root = "/data"

  [grpc.services.storageprovidersvc.drivers.owncloud]
  datadirectory = "/data"

  [grpc.services.usershareprovidersvc]
  driver = "local"

  [grpc.services.usershareprovidersvc.drivers.local]
  root = "/data"

  [grpc.services.usershareprovidersvc.drivers.owncloud]
  datadirectory = "/data"

  [grpc.services.appregistrysvc]
  driver = "static"

  [grpc.services.appregistrysvc.static.rules]
  "application/x-root" = "root.cern/js/latest"

  [grpc.services.appprovidersvc]
  driver = "demo"

  [grpc.services.appprovidersvc.demo]
  iframe_ui_provider = "http://localhost:9998/iframe"
  ```
  3. (Alternative way) Instead of above two steps, you can also use my local repo with above steps already done: https://github.com/Mohitty/reva_preferences . Then go to step 4.
  4. Run the following commands in order, from the root of the repo:
    - `make`
    - `cmd/revad/revad -c local.toml -p revad.pid | jq`
    
- Navigate to localhost:8300 and login. The login instruction are there on the login page itself.
- After login, there is a menu button on the top left of the page. There is a `preferences` option present there. You can navigate to the app from there.
- To check the root viewer app, there must be a root file present in the data directory. In that case, on opening the file, there will be a Root Viewer option to open it. You will need to associate application provider using the preferences app first.
