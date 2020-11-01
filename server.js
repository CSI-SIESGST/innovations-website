var express = require('express');
var app = express();
var http = require('http').Server(app)
var path = require('path');

app.get('/',function(request,response){
  response.sendFile(path.join(__dirname+'/html'+'/index.html'));
});

http.listen(4000,function(){
  console.log('listening on port 4000...');
});
