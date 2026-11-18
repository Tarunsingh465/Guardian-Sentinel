"""
Guardian-Sentinel Model A: Deep Multilayer Perceptron (MLP) Classifier
Primary supervised neural architecture for multi-class attack classification.
Designed for CPU execution: 128 -> 64 -> 32 neurons with Dropout and Batch Normalization.
"""

import os
from pathlib import Path
from typing import Tuple, List, Optional
import numpy as np

# Suppress TF logs
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

def create_mlp_model(
    input_dim: int = 80,
    num_classes: int = 4,
    learning_rate: float = 0.001,
    dropout_rate: float = 0.3
):
    """
    Constructs the Deep MLP architecture using TensorFlow/Keras functional API
    with L2 kernel regularization and Dropout to prevent overfitting.
    """
    import tensorflow as tf
    from tensorflow.keras.models import Model
    from tensorflow.keras.layers import Input, Dense, Dropout, BatchNormalization
    from tensorflow.keras.optimizers import Adam
    from tensorflow.keras.regularizers import l2

    reg = l2(1e-4)
    inputs = Input(shape=(input_dim,), name="flow_input_features")

    # Layer 1
    x = Dense(128, activation="relu", kernel_regularizer=reg, name="dense_128")(inputs)
    x = BatchNormalization(name="bn_1")(x)
    x = Dropout(dropout_rate, name="drop_1")(x)

    # Layer 2
    x = Dense(64, activation="relu", kernel_regularizer=reg, name="dense_64")(x)
    x = BatchNormalization(name="bn_2")(x)
    x = Dropout(dropout_rate, name="drop_2")(x)

    # Layer 3
    x = Dense(32, activation="relu", kernel_regularizer=reg, name="dense_32")(x)
    x = Dropout(dropout_rate, name="drop_3")(x)

    # Multi-class output
    outputs = Dense(num_classes, activation="softmax", name="attack_class_probs")(x)

    model = Model(inputs=inputs, outputs=outputs, name="Guardian_MLP_Classifier")
    optimizer = Adam(learning_rate=learning_rate)

    model.compile(
        optimizer=optimizer,
        loss="categorical_crossentropy",
        metrics=["accuracy"]
    )

    return model

def get_training_callbacks(checkpoint_path: Path, patience: int = 5):
    """
    Standard production callbacks: EarlyStopping, ModelCheckpoint, LearningRateScheduler.
    """
    from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau

    callbacks = [
        EarlyStopping(
            monitor="val_loss",
            patience=patience,
            restore_best_weights=True,
            verbose=1
        ),
        ModelCheckpoint(
            filepath=str(checkpoint_path),
            monitor="val_loss",
            save_best_only=True,
            verbose=1
        ),
        ReduceLROnPlateau(
            monitor="val_loss",
            factor=0.5,
            patience=3,
            min_lr=1e-5,
            verbose=1
        )
    ]
    return callbacks
