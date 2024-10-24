extAlert = org.parosproxy.paros.control.Control.getSingleton().
    getExtensionLoader().getExtension(
        org.zaproxy.zap.extension.alert.ExtensionAlert.NAME) 

if (extAlert != null) {
    var alerts = extAlert.getAllAlerts()

    for (var i = 0; i < alerts.length; i++) {
          var alert = alerts[i]
          var id = alert.getPluginId()
          var name = alert.getName()
          
          switch (id){ 
            case 10038: //CSP - Header Not Set

              for (var scan = 0; scan < alerts.length; scan++) {
                  var next_alert = alerts[scan]
                  
                  if(id == alerts[scan].getPluginId()) {
                      extAlert.deleteAlert(next_alert)
                  }
              }
              
              extAlert.updateAlert(alert)
              break;
            
            case 10020: // Missing Anti-clickjacking Header 
               for (var scan = 0; scan < alerts.length; scan++) {
                  var next_alert = alerts[scan]
                  
                  if(id == alerts[scan].getPluginId()) {
                      extAlert.deleteAlert(next_alert)
                  }
              }
              
              extAlert.updateAlert(alert)
              break;
            case 10021: // X-Content-Type-Options Header Missing
               for (var scan = 0; scan < alerts.length; scan++) {
                  var next_alert = alerts[scan]
                  
                  if(id == alerts[scan].getPluginId()) {
                      extAlert.deleteAlert(next_alert)
                  }
              }
              
              extAlert.updateAlert(alert)
              break;
            default:
              break;
          }
    }
}