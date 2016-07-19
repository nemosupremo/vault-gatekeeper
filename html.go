package main

import (
	"html/template"
)

const htmlTemplateVal = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>Vault Gatekeeper</title>

    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">

    <style>
      .active-form .form-section {
        display: none;
      }
      .active-form.active-app-id .visible-app-id {
        display: block;
      }
      .active-form.active-github .visible-github {
        display: block;
      }
      .active-form.active-userpass .visible-userpass {
        display: block;
      }
      .active-form.active-token .visible-token {
        display: block;
      }
      .active-form.active-cubby .visible-cubby {
        display: block;
      }
      .active-form.active-wrapped-token .visible-wrapped-token {
        display: block;
      }
      .status-unsealed {
        display: {{.StatusUnsealed}};
      }
      .status-sealed {
        display: {{.StatusSealed}};
      }
    </style>
  </head>
  <body>
    <nav class="navbar navbar-inverse navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <a class="navbar-brand" href="#">Vault Gatekeeper</a>
        </div>
        <div id="navbar" class="collapse navbar-collapse">
        </div><!--/.nav-collapse -->
      </div>
    </nav>

    <div class="container" style="padding-top:80px;">
      <div class="row">
        <div class="col-sm-4">
          <ul class="list-group">
            <li class="list-group-item"><strong>Status:</strong> {{.Status}}</li>
            <li class="list-group-item">Token Requests: {{.Stats.Requests}}</li>
            <li class="list-group-item">Successful Requests: {{.Stats.Successful}}</li>
            <li class="list-group-item">Denied Requests: {{.Stats.Denied}}</li>
            <li class="list-group-item">Uptime: {{.Uptime}}</li>
            <li class="list-group-item">Version: {{.Version}}</li>
          </ul>
        </div>
        <div class="col-sm-8 status-unsealed">
        	<form id="form-unsealed" method="POST" action="/seal">
        		<div class="text-right">
              		<button type="submit" class="btn btn-danger text-right">Seal</button>
            	</div>
        	</form>
        </div>
        <div class="col-sm-8 status-sealed">
          <h1 style="margin-top:10px">Vault Authenication</h1>
          <form id="form" method="POST" action="/unseal">
            <div class="form-group">
              <label for="auth_type">Authenication Type</label>
              <select id="auth_type" class="form-control" name="auth_type">
                <option value="app-id">App ID</option>
                <option value="github">GitHub</option>
                <option value="userpass">Username &amp; Password</option>
                <option value="cubby">Cubby Method</option>
                <option value="wrapped-token">Wrapped Token Method</option>
                <option value="token">Token</option>
              </select>
            </div>
            <div class="form-section visible-app-id">
              <div class="form-group">
                <label for="app-id_appid">App ID: App ID</label>
                <input type="text" class="form-control" id="app-id_appid" name="app-id_appid">
              </div>
              <div class="form-group row">
                <div class="col-xs-6">
                  <label for="app-id_userid_method">App ID: User ID</label>
                  <select id="app-id_userid_method" class="form-control" name="app-id_userid_method">
                    <option value="mac">Mac Address (specify interface name)</option>
                    <option value="file">File Value (specify path)</option>
                  </select>
                </div>
                <div class="col-xs-6">
                  <label for="app-id_userid_data">App ID: User ID Data</label>
                  <input type="text" class="form-control" id="app-id_userid_data" name="app-id_userid_data">
                </div>
              </div>
              <div class="form-group row">
                <div class="col-xs-6">
                  <label for="app-id_userid_hash">App ID: User ID Hash Function</label>
                  <select id="app-id_userid_hash" class="form-control" name="app-id_userid_hash">
                    <option value="">none</option>
                    <option value="sha256">sha256</option>
                    <option value="sha1">sha1</option>
                    <option value="md5">md5</option>
                  </select>
                </div>
                <div class="col-xs-6">
                  <label for="app-id_userid_salt">App ID: User ID Hash Salt</label>
                  <input type="text" class="form-control" id="app-id_userid_salt" name="app-id_userid_salt">
                </div>
              </div>
            </div>
            <div class="form-group form-section visible-github">
              <label for="github_token">GitHub: Personal Token</label>
              <input type="text" class="form-control" id="github_token" name="github_token">
            </div>
            <div class="form-section visible-userpass">
              <div class="form-group">
                <label for="username_username">Username: Username</label>
                <input type="text" class="form-control" id="username_username" name="username_username">
              </div>
              <div class="form-group">
                <label for="username_password">Username: Password</label>
                <input type="password" class="form-control" id="username_password" name="username_password">
              </div>
            </div>
            <div class="form-group form-section visible-token">
              <label for="token_token">Token: Token</label>
              <input type="text" class="form-control" id="token_token" name="token_token">
            </div>
            <div class="form-section visible-cubby">
              <div class="form-group">
                <label for="cubby_token">Cubby Method: Token</label>
                <input type="text" class="form-control" id="cubby_token" name="cubby_token">
              </div>
              <div class="form-group">
                <label for="cubby_path">Cubby Method: Path</label>
                <input type="password" class="form-control" id="cubby_path" name="cubby_path" placeholder="/vault-token">
              </div>
            </div>
            <div class="form-section visible-wrapped-token">
              <div class="form-group">
                <label for="wrapped_token">Wrapped Token Method: Temp Token</label>
                <input type="text" class="form-control" id="wrapped_token" name="wrapped_token">
              </div>
            </div>
            <div class="text-right">
              <button type="submit" class="btn btn-primary text-right">Unseal</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </body>
  <script>
    var form = document.getElementById("form");
    var authSelect = document.getElementById("auth_type");
    var activeSection = "";
    var ux = function(v) {
      if (activeSection == "") {
        form.classList.add("active-form", "active-"+v);
        activeSection = v;
        return;
      }
      form.classList.remove("active-"+activeSection)
      form.classList.add("active-"+v);
      activeSection = v;
    };
    ux(authSelect.value);
    authSelect.addEventListener("change", function(){ux(authSelect.value)})
  </script>
</html>
`

var statusPage = template.Must(template.New("status").Parse(htmlTemplateVal))
