from snort import snortdb

class TestSnort:

    def test_init(self):
        self.s = snortdb.sdb()

    def teardown_class(self):
        pass

    def test_where(self):
        self.s.setwhere(range="hour", span=24)
        #assert self.s.where == "timestamp > current_timestamp - interval '24 hour' and timestamp < current_timestamp - interval '0 hour'"


    def test_find(self):
        self.s.limit=200
        data = self.s.find()
        data=list(data)
        assert isinstance(data, list)
        assert len(data) == 200 #in 24 hours I should definitely have 200+ alerts
        for row in data:
            yield self.check_row, row

    def check_row(self, row):
        assert isinstance(row, dict)
        for col in 'ip_src ip_dst sport dport proto data timestamp sig'.split():
            assert col in row
