var interval = 2000;

var internalsEnabled = false;

$(function() {
  $.get("/internals", function() {
    internalsEnabled = true;
  })
  .always(function() {
    updateMetrics();
    //updateTail();
  })
});

var tailId = 0;

function updateMetrics() {
  var metrics = $.getJSON( "/debug/vars", function(d) {
    var template = Handlebars.compile( $("#header-messages-template").html() );
    var messages = [];
    if(internalsEnabled) {
      messages.push({"message": "Also available: <a href='/internals'>Internals: heap, cache, objects, etc.</a>"});
    }
    var html    = template({
      "header": {
        "messages": messages
      }
    });
    $("#headerpanel").html(html);
    var template = Handlebars.compile( $("#statspanel-template").html() );
    var html    = template(d);
    $("#statspanel").html(html);
    var template = Handlebars.compile( $("#stats-template").html() );
    var html    = template(d);
    $("#stats").html(html);
    var template = Handlebars.compile( $("#servers-template").html() );
    var html    = template(d);
    $("#servers").html(html);
  })
  .fail(function() {
    $("#statspanel").html("Error!");
  })
  .always(function() {
    setTimeout(updateMetrics,interval);
  });
}
function updateTail() {
  var tail = $.getJSON( "/tail/" + tailId , function(d) {
    d.forEach(function(e) {
      if (e.Id > tailId) {
        tailId = e.Id;
      }
    });
    var template = Handlebars.compile( $("#tail-template").html() );
    var html    = template(d);
    $(html).hide().prependTo("#tail").fadeIn(2000);
  })
  .fail(function() {
    $("#tail").html("Error!");
  })
  .always(function() {
    setTimeout(updateTail,interval);
  });
}

Handlebars.registerHelper('dateRelative', function(context, block) {
  if (window.moment) {
    //return moment(context).fromNow();
    return moment(context).format();
  }else{
    return context;
  };
});

