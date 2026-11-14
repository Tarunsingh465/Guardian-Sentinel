"""
Guardian-Sentinel Model C: Deep Keras Autoencoder for Zero-Day Anomaly Hunting
Undercomplete bottleneck architecture (93 -> 64 -> 32 -> 16 -> 8 -> 16 -> 32 -> 64 -> 93)
Trained strictly on Benign traffic. Reconstruction Mean Squared Error (MSE) measures out-of-distribution distance.
"""

import os
from pathlib import Path
from typing import Tuple, Dict, Any, Optional
import numpy as np

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

def create_keras_autoencoder(input_dim: int = 93, latent_dim: int = 8):
    """
    Constructs Encoder, Decoder, and Autoencoder models using Keras Functional API.
    """
    import tensorflow as tf
    from tensorflow.keras.models import Model
    from tensorflow.keras.layers import Input, Dense, BatchNormalization
    from tensorflow.keras.optimizers import Adam

    inputs = Input(shape=(input_dim,), name="autoencoder_input")

    # Encoder
    e = Dense(64, activation="relu", name="enc_dense_64")(inputs)
    e = BatchNormalization(name="enc_bn_1")(e)
    e = Dense(32, activation="relu", name="enc_dense_32")(e)
    e = BatchNormalization(name="enc_bn_2")(e)
    e = Dense(16, activation="relu", name="enc_dense_16")(e)

    # Bottleneck Latent Space
    latent = Dense(latent_dim, activation="relu", name="latent_bottleneck")(e)

    # Decoder
    d = Dense(16, activation="relu", name="dec_dense_16")(latent)
    d = BatchNormalization(name="dec_bn_1")(d)
    d = Dense(32, activation="relu", name="dec_dense_32")(d)
    d = BatchNormalization(name="dec_bn_2")(d)
    d = Dense(64, activation="relu", name="dec_dense_64")(d)
    outputs = Dense(input_dim, activation="linear", name="reconstructed_flow")(d)

    autoencoder = Model(inputs=inputs, outputs=outputs, name="Guardian_Deep_Autoencoder")
    encoder = Model(inputs=inputs, outputs=latent, name="Guardian_Flow_Encoder")

    autoencoder.compile(
        optimizer=Adam(learning_rate=0.001),
        loss="mse"
    )

    return autoencoder, encoder

def calibrate_reconstruction_threshold(autoencoder, X_benign_val: np.ndarray, percentile: float = 95.0) -> float:
    """
    Calibrates decision threshold on held-out benign validation flows.
    """
    reconstructed = autoencoder.predict(X_benign_val, batch_size=256, verbose=0)
    mse_errors = np.mean(np.square(X_benign_val - reconstructed), axis=1)
    threshold = float(np.percentile(mse_errors, percentile))
    return threshold
