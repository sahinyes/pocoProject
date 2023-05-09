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