$(document).ready(function() {
    $('#vulnbutton').click(function(event) {
        event.preventDefault();  // Prevent the default form submission

        var formData = $('#vulnbutton').val();       

        // Prompt-like behavior for the iframe source
        var vulnbutton = document.getElementById('vulnbutton')
        var promptElement = document.createElement('p');
        promptElement.textContent = "Scanning for vulnerabilities " + formData;
        document.body.insertBefore(promptElement, iframe);

        var iframe = document.createElement('iframe');

        iframe.src = "/vulnscan?url=" + formData;
        iframe.id = 'vulnframe';
        iframe.allowFullscreen = true;
        allowtransparency = true;
        frameborder = 0;
        vulnbutton.disabled = true;

        document.body.appendChild(iframe);

    },);
});



$(document).ready(function() {
    $('#dirbutton').click(function(event) {
        event.preventDefault();  // Prevent the default form submission
        

        // Prompt-like behavior for the iframe source
        var formData = $('#dirbutton').val();       
        var dirbutton = document.getElementById('dirbutton');
        var promptElement = document.createElement('p');
        promptElement.textContent = "Scanning directories for " + formData;
        document.body.insertBefore(promptElement, iframe);

        // Here creating iframes 
        var iframe = document.createElement('iframe');

        iframe.src = "/dirscan?url=" + formData;
        iframe.id = 'vulnframe';
        iframe.allowFullscreen = true;
        allowtransparency = true;
        frameborder = 0;
        dirbutton.disabled = true;
        document.body.appendChild(iframe);
        

    },);
});



$(document).ready(function() {
    $('#ipbutton').click(function(event) {
        event.preventDefault();  // Prevent the default form submission
        
        // Prompt-like behavior for the iframe source
        var formData = $('#ipbutton').val();       
        var ipbutton = document.getElementById('ipbutton');
        var promptElement = document.createElement('p');
        promptElement.textContent = "Scanning directories for " + formData;
        document.body.insertBefore(promptElement, iframe);

        // Here creating iframes 
        var iframe = document.createElement('iframe');
        iframe.src = "/ipscan?url=" + formData;
        iframe.id = 'vulnframe';
        iframe.allowFullscreen = true;
        allowtransparency = true;
        frameborder = 0;
        ipbutton.disabled = true;
        document.body.appendChild(iframe);
        

    },);
});


document.getElementById('reconbutton').addEventListener('click', function() {
    	
    document.getElementById('dashboard').submit();
    document.getElementById('dashboard').style.display = "none";
    var img = document.createElement('img');
    img.src = "https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExMDdiODIzNmUwMWU1ODAzYzYxMDM5ZTI3NTc0NzYxZDRjNzcwOWI3ZCZlcD12MV9pbnRlcm5hbF9naWZzX2dpZklkJmN0PWc/gJ3mEToTDJn3LT6kCT/giphy.gif";
    img.id = 'animePurple';
    document.body.appendChild(img);
  });