module IO::Buffered
  # Like `#peek`, but while fewer than *size* bytes are buffered it reads
  # more after them, until *size* bytes are buffered or the IO is at EOF.
  # Nothing is consumed. Returns all buffered bytes. *size* is capped at
  # `buffer_size`. Uses the same internals as the stdlib's `#peek`, check
  # them when upgrading Crystal.
  def peek(size : Int) : Bytes
    peeked = peek
    size = Math.min(size, @buffer_size)
    while !peeked.empty? && peeked.size < size
      in_buffer = @in_buffer
      # Move the buffered bytes to the start of the buffer, to read more after them
      unless peeked.to_unsafe == in_buffer
        in_buffer.move_from(peeked.to_unsafe, peeked.size)
        @in_buffer_rem = Slice.new(in_buffer, peeked.size)
      end
      count = unbuffered_read(Slice.new(in_buffer + peeked.size, @buffer_size - peeked.size)).to_i
      break if count.zero?
      @in_buffer_rem = peeked = Slice.new(in_buffer, peeked.size + count)
    end
    peeked
  end
end
