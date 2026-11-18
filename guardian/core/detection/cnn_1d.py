"""
Guardian-Sentinel Model B: Lightweight 1D Convolutional Neural Network (1D-CNN)
Experimental architecture evaluating whether localized feature grouping
(e.g., contiguous packet stats vs timing stats) provides inductive advantages over MLP.
"""

import os
from typing import Tuple, List, Optional
import numpy as np

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

def create_1d_cnn_model(
    input_dim: int = 80,
    num_classes: int = 4,
    learning_rate: float = 0.001
):
    """
    Constructs a lightweight 1D-CNN for tabular flow sequences with regularization.
    Input shape is reshaped to (input_dim, 1) for Conv1D processing.
    """
    import tensorflow as tf
    from tensorflow.keras.models import Model
    from tensorflow.keras.layers import (
        Input, Conv1D, MaxPooling1D, BatchNormalization,
        Dropout, Flatten, Dense
    )
    from tensorflow.keras.optimizers import Adam
    from tensorflow.keras.regularizers import l2

    reg = l2(1e-4)

    # Reshape input to (input_dim, 1) channel
    inputs = Input(shape=(input_dim, 1), name="conv_flow_inputs")

    # Conv Block 1
    x = Conv1D(filters=32, kernel_size=3, padding="same", activation="relu", kernel_regularizer=reg, name="conv1d_1")(inputs)
    x = BatchNormalization()(x)
    x = MaxPooling1D(pool_size=2, name="pool_1")(x)
    x = Dropout(0.25)(x)

    # Conv Block 2
    x = Conv1D(filters=64, kernel_size=3, padding="same", activation="relu", kernel_regularizer=reg, name="conv1d_2")(x)
    x = BatchNormalization()(x)
    x = MaxPooling1D(pool_size=2, name="pool_2")(x)
    x = Dropout(0.25)(x)

    # Dense Classification Head
    x = Flatten(name="flatten")(x)
    x = Dense(64, activation="relu", kernel_regularizer=reg, name="dense_conv_head")(x)
    x = Dropout(0.35)(x)
    outputs = Dense(num_classes, activation="softmax", name="attack_class_probs")(x)

    model = Model(inputs=inputs, outputs=outputs, name="Guardian_1D_CNN_Classifier")
    optimizer = Adam(learning_rate=learning_rate)

    model.compile(
        optimizer=optimizer,
        loss="categorical_crossentropy",
        metrics=["accuracy"]
    )

    return model
