document.addEventListener('DOMContentLoaded', function() {
  const chatList = document.querySelectorAll('.chat');
  const chatMessages = document.querySelector('.chat-messages');
  const chatInput = document.querySelector('.chat-input');

  // Initial state: Hide chat input and chat messages
  chatInput.classList.add('chat-hidden');
  chatMessages.classList.add('chat-hidden');

  chatList.forEach(function(chat) {
    chat.addEventListener('click', function() {
      // Clear existing messages
      chatMessages.innerHTML = '';

      // Simulate loading messages
      for (let i = 0; i < 10; i++) {
        const message = document.createElement('div');
        message.classList.add('message');
        message.textContent = 'Message ' + (i + 1);
        chatMessages.appendChild(message);
      }

      // Show chat input and chat messages
      chatInput.classList.remove('chat-hidden');
      chatMessages.classList.remove('chat-hidden');
    });
  });
});
