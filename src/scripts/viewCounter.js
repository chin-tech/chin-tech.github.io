async function viewCounter() {

    const viewValueElement = document.getElementById("view_value");

    // IMPORTANT: This URL will come from your Terraform output: websocket_api_endpoint
    // It will look something like: wss://<api-id>.execute-api.<region>.amazonaws.com/prod
    const API_GATEWAY_WEBSOCKET_URL = "wss://vtp95vkir5.execute-api.us-east-1.amazonaws.com/prod"; 

    let socket;

    async function connectWebSocket() {
        console.log("Attempting to connect to WebSocket...");
        socket = new WebSocket(API_GATEWAY_WEBSOCKET_URL);

        socket.onopen = (event) => {
            console.log("WebSocket connection established!", event);
            // The $connect route on API Gateway triggers DBUpdater to increment count
            // and DBStreamProcessor will push the new count. No need for initial fetch.
        };

        socket.onmessage = (event) => {
            console.log("Message received:", event.data);
            const msg = JSON.parse(event.data);
            if (viewValueElement && msg && typeof msg.count === 'number') {
                viewValueElement.textContent = msg.count;
            } else {
                console.warn("Invalid message format or 'view_value' element not found.", msg);
            }
        };

        socket.onclose = (event) => {
            console.warn("WebSocket connection closed:", event.code, event.reason);
            setTimeout(connectWebSocket, 3000);
        };

        socket.onerror = (error) => {
            console.error("WebSocket error:", error);
            socket.close();
        };
    }

    connectWebSocket(); 
}


document.addEventListener('DOMContentLoaded', viewCounter );

