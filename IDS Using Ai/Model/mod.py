import torch
import torch.nn as nn
import torch.nn.functional as F
import pandas as pd

class ResidualEnhancedNeuralNet(nn.Module):
    def __init__(self, input_size, hidden_size, output_size, dropout_prob=0.5):
        super(ResidualEnhancedNeuralNet, self).__init__()
        self.input_layer = nn.Linear(input_size, hidden_size)
        self.bn1 = nn.BatchNorm1d(hidden_size)
        self.hidden_layer1 = nn.Linear(hidden_size, hidden_size)
        self.hidden_layer2 = nn.Linear(hidden_size, hidden_size)
        self.output_layer = nn.Linear(hidden_size, output_size)
        self.dropout = nn.Dropout(dropout_prob)
        self.activation = nn.ReLU()

    def forward(self, x):
        # Input to first layer
        x = self.activation(self.bn1(self.input_layer(x)))

        # Residual connection 1
        residual = x
        x = self.activation(self.hidden_layer1(x))
        x = self.dropout(x)
        x += residual  # Add residual connection

        # Residual connection 2
        residual = x
        x = self.activation(self.hidden_layer2(x))
        x = self.dropout(x)
        x += residual  # Add residual connection

        # Output layer
        x = self.output_layer(x)
        return x




def predict(data):
    classes = ['Benign', 'backdoor', 'ddos', 'dos', 'injection', 'mitm',
       'password', 'ransomware', 'scanning', 'xss']

    model = torch.load('./model.pt', weights_only=False ,map_location=torch.device('cpu'))
    model.eval()
    data = torch.tensor(data.values , dtype=torch.float32)
    out = model(data)
    _, predicted = torch.max(out, 1)
    return predicted




data = pd.read_csv('test.csv')
print(data)
print(predict(data))