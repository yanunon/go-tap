## Go-Tap ##

可运行在Google App Engine和OpenShift上的Twitter API 代理程序

## 使用 ##
1. Google App Engine
>修改文件[gae/app.yaml](https://github.com/yanunon/go-tap/blob/master/gae/app.yaml)，将`YOUR_APP_ID`修改为你在GAE上的app_id。
>
>修改文件[gae/server/gae.go](https://github.com/yanunon/go-tap/blob/master/gae/server/gae.go)，将`KEY`和`SECRET`改为你的Twitter应用程序的相应值，`HOST`改为对应的`app_id.appspot.com`，`DATA_DIR`设为""即可。

2. OpenShift
>修改文件[openshift/diy/go-tap.go](https://github.com/yanunon/go-tap/blob/master/openshift/diy/go-tap.go)，将`KEY`和`SECRET`改为你的Twitter应用程序的相应值，`HOST`改为相应的`your_id.rhcloud.com`，your_id改为你在OpenShift上相应的名称即可。
>
>本地编译后通过git上传。具体参考项目[golang-openshift](https://github.com/gcmurphy/golang-openshift)。
