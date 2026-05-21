require 'spec_helper'

describe Message do
  describe '.number_of_bits_up_to' do
    it 'returns the correct number of bits' do
      expect(CoRE::CoAP.number_of_bits_up_to(1)).to eq(0)
      expect(CoRE::CoAP.number_of_bits_up_to(16)).to eq(4)
      expect(CoRE::CoAP.number_of_bits_up_to(32)).to eq(5)
      expect(CoRE::CoAP.number_of_bits_up_to(128)).to eq(7)
    end
  end

  describe '.path_encode' do
    it 'correctly encodes path segments' do
      expect(CoRE::CoAP.path_encode([])).to eq("/")
      expect(CoRE::CoAP.path_encode(["foo"])).to eq("/foo")
      expect(CoRE::CoAP.path_encode(["foo", "bar"])).to eq("/foo/bar")
      expect(CoRE::CoAP.path_encode(["f.o", "b-r"])).to eq("/f.o/b-r")
      expect(CoRE::CoAP.path_encode(["f(o", "b)r"])).to eq("/f(o/b)r")
      expect(CoRE::CoAP.path_encode(["foo", "b/r"])).to eq("/foo/b%2Fr")
      expect(CoRE::CoAP.path_encode(["foo", "b&r"])).to eq("/foo/b&r")
      expect(CoRE::CoAP.path_encode(["føo", "bär"])).to eq("/f%C3%B8o/b%C3%A4r")
    end
  end

  describe '.query_encode' do
    it 'correctly encodes query parameters' do
      expect(CoRE::CoAP.query_encode([])).to eq("")
      expect(CoRE::CoAP.query_encode([""])).to eq("?")
      expect(CoRE::CoAP.query_encode(["foo"])).to eq("?foo")
      expect(CoRE::CoAP.query_encode(["foo", "bar"])).to eq("?foo&bar")
      expect(CoRE::CoAP.query_encode(["f.o", "b-r"])).to eq("?f.o&b-r")
      expect(CoRE::CoAP.query_encode(["f(o", "b)r"])).to eq("?f(o&b)r")
      expect(CoRE::CoAP.query_encode(["foo", "b/r"])).to eq("?foo&b/r")
      expect(CoRE::CoAP.query_encode(["foo", "b&r"])).to eq("?foo&b%26r")
      expect(CoRE::CoAP.query_encode(["føo", "bär"])).to eq("?f%C3%B8o&b%C3%A4r")
    end
  end

  describe '.path_decode' do
    it 'correctly decodes paths' do
      expect(CoRE::CoAP.path_decode("/")).to eq([])
      expect(CoRE::CoAP.path_decode("/foo")).to eq(["foo"])
      expect(CoRE::CoAP.path_decode("/foo/")).to eq(["foo", ""])
      expect(CoRE::CoAP.path_decode("/foo/bar")).to eq(["foo", "bar"])
      expect(CoRE::CoAP.path_decode("/f.o/b-r")).to eq(["f.o", "b-r"])
      expect(CoRE::CoAP.path_decode("/f(o/b)r")).to eq(["f(o", "b)r"])
      expect(CoRE::CoAP.path_decode("/foo/b%2Fr")).to eq(["foo", "b/r"])
      expect(CoRE::CoAP.path_decode("/foo/b&r")).to eq(["foo", "b&r"])
      expect(CoRE::CoAP.path_decode("/f%C3%B8o/b%C3%A4r")).to eq(["føo", "bär"])
    end
  end

  describe '.query_decode' do
    it 'correctly decodes query strings' do
      expect(CoRE::CoAP.query_decode("")).to eq([])
      expect(CoRE::CoAP.query_decode("?")).to eq([])
      expect(CoRE::CoAP.query_decode("?foo")).to eq(["foo"])
      expect(CoRE::CoAP.query_decode("?foo&")).to eq(["foo", ""])
      expect(CoRE::CoAP.query_decode("?foo&bar")).to eq(["foo", "bar"])
      expect(CoRE::CoAP.query_decode("?f.o&b-r")).to eq(["f.o", "b-r"])
      expect(CoRE::CoAP.query_decode("?f(o&b)r")).to eq(["f(o", "b)r"])
      expect(CoRE::CoAP.query_decode("?foo&b/r")).to eq(["foo", "b/r"])
      expect(CoRE::CoAP.query_decode("?foo&b%26r")).to eq(["foo", "b&r"])
      expect(CoRE::CoAP.query_decode("?f%C3%B8o&b%C3%A4r")).to eq(["føo", "bär"])
    end
  end

  describe '.scheme_and_authority_encode' do
    it 'correctly encodes scheme and authority' do
      expect(CoRE::CoAP.scheme_and_authority_encode("foo.bar", 4711)).to eq("coap://foo.bar:4711")
      expect(CoRE::CoAP.scheme_and_authority_encode("foo.bar", "4711")).to eq("coap://foo.bar:4711")
      expect { CoRE::CoAP.scheme_and_authority_encode("foo.bar", "baz") }.to raise_error(ArgumentError)
      expect(CoRE::CoAP.scheme_and_authority_encode("bar.baz", 5683)).to eq("coap://bar.baz")
      expect(CoRE::CoAP.scheme_and_authority_encode("bar.baz", "5683")).to eq("coap://bar.baz")
    end
  end

  describe '.scheme_and_authority_decode' do
    it 'correctly decodes scheme and authority' do
      expect(CoRE::CoAP.scheme_and_authority_decode("coap://foo.bar:4711")).to eq([nil, "foo.bar", 4711])
      expect(CoRE::CoAP.scheme_and_authority_decode("coap://foo.bar")).to eq([nil, "foo.bar", 5683])
      expect(CoRE::CoAP.scheme_and_authority_decode("coap://[foo:bar]:4711")).to eq([nil, "foo:bar", 4711])
      expect(CoRE::CoAP.scheme_and_authority_decode("coap://%5Bfoo:bar%5D")).to eq([nil, "foo:bar", 5683])
    end
  end

  describe 'Message parse and roundtrip' do
    it 'should parse and serialize options and payload correctly' do
      input = "\x44\x02\x12\xA0abcd\x41A\x7B.well-known\x04core\x0D\x04rhabarbersaftglas\xFFfoobar".force_encoding("BINARY")
      output = CoRE::CoAP.parse(input)
      expect(output.to_wire).to eq(input)
    end

    it 'handles fenceposting for standard options' do
      m = CoRE::CoAP::Message.new(:con, :get, 4711, "Hello")
      m.options = { max_age: 987654321, if_none_match: true }
      me = m.to_wire
      m2 = CoRE::CoAP.parse(me)
      m.options = CoRE::CoAP::DEFAULTING_OPTIONS.merge(m.options)
      expect(m2).to eq(m)
    end

    it 'handles fenceposting for custom options' do
      m = CoRE::CoAP::Message.new(:con, :get, 4711, "Hello")
      m.options = { 4712 => ["foo"], 256 => ["bar"] }
      me = m.to_wire
      m2 = CoRE::CoAP.parse(me)
      m.options = CoRE::CoAP::DEFAULTING_OPTIONS.merge(m.options)
      expect(m2).to eq(m)
    end

    it 'handles empty payload with custom options' do
      m = CoRE::CoAP::Message.new(:con, :get, 4711, "")
      m.options = { 4712 => ["foo"], 256 => ["bar"], 65534 => ["abc" * 100] }
      me = m.to_wire
      m2 = CoRE::CoAP.parse(me)
      m.options = CoRE::CoAP::DEFAULTING_OPTIONS.merge(m.options)
      expect(m2).to eq(m)
    end

    it 'encodes and decodes option numbers correctly' do
      [0, 2, 10, 100, 1000, 10000, 65534].each do |on|
        next if CoRE::CoAP::OPTIONS[on]
        m = CoRE::CoAP::Message.new(:con, :get, 4711, "Hello")
        m.options = { on => [""] }
        me = m.to_wire
        m2 = CoRE::CoAP.parse(me)
        m.options = CoRE::CoAP::DEFAULTING_OPTIONS.merge(m.options)
        expect(m2).to eq(m)
      end
    end

    it 'encodes and decodes option lengths correctly' do
      [0, 1, 5, 12, 13, 14, 255, 269, 500, 1034].each do |ol|
        m = CoRE::CoAP::Message.new(:con, :get, 4711, "Hello")
        m.options = { 98 => ["x" * ol] }
        me = m.to_wire
        m2 = CoRE::CoAP.parse(me)
        m.options = CoRE::CoAP::DEFAULTING_OPTIONS.merge(m.options)
        expect(m2).to eq(m)
      end
    end
  end

  describe 'RFC 7252 Conformance Validations' do
    it 'rejects message if token length is greater than 8' do
      invalid_header = "\x49\x01\x00\x01".force_encoding("BINARY") + "A" * 9
      expect { CoRE::CoAP.parse(invalid_header) }.to raise_error(ArgumentError, /token length/)
    end

    it 'rejects message if payload marker 0xFF is present but payload is empty' do
      invalid_packet = "\x40\x01\x00\x01\xFF".force_encoding("BINARY")
      expect { CoRE::CoAP.parse(invalid_packet) }.to raise_error(ArgumentError, /Payload marker/)
    end

    it 'rejects message if an unrecognized critical option is received' do
      m = CoRE::CoAP::Message.new(:con, :get, 4711, "Hello")
      m.options = { 99 => [""] }
      me = m.to_wire
      expect { CoRE::CoAP.parse(me) }.to raise_error(ArgumentError, /unrecognized critical option/)
    end

    it 'accepts message if an unrecognized elective option is received' do
      m = CoRE::CoAP::Message.new(:con, :get, 4711, "Hello")
      m.options = { 98 => [""] }
      me = m.to_wire
      expect { CoRE::CoAP.parse(me) }.not_to raise_error
    end
  end
end
