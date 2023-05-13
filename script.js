( function ( parent ){
"use strict ";
  
var app = parent .app = parent .app || {};

app.utils = ( function (){
  
var self = this;
  
var module = {
stringPadRight : function (str , len , ch) {
var chx = ch || ' ';
while(str.length < len) {
str += chx;
}
return str;
},
stringPadLeft : function (s, len , ch) {
var str = '', chx = ch || ' ';
while(str.length + s.length < len) {
str += chx;
}
str += s;
return str;
},

