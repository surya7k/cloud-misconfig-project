import unittest


class FeatureSchemaTests(unittest.TestCase):
    def test_train_and_predict_share_feature_schema(self):
        from src import schema
        from src import predict
        from src import train

        self.assertEqual(train.BASE_FEATURE_COLS, schema.BASE_FEATURE_COLS)
        self.assertEqual(train.S3_DERIVED_COLS, schema.S3_DERIVED_COLS)
        self.assertEqual(train.EXTENDED_FEATURE_COLS, schema.EXTENDED_FEATURE_COLS)
        self.assertEqual(train.FEATURE_COLS, schema.FEATURE_COLS)
        self.assertEqual(predict.FEATURE_COLS, schema.FEATURE_COLS)

    def test_schema_has_expected_model_width(self):
        from src import schema

        self.assertEqual(len(schema.FEATURE_COLS), 26)
        self.assertEqual(
            schema.FEATURE_COLS,
            schema.BASE_FEATURE_COLS
            + schema.S3_DERIVED_COLS
            + schema.EXTENDED_FEATURE_COLS,
        )


if __name__ == "__main__":
    unittest.main()
