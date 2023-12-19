    def shiftColumns(self, state):
        # Transpose the state to make column operations easier
        state = list(map(list, zip(*state)))

        # Shift each column by its index
        state = [state[i][-i:] + state[i][:-i] for i in range(4)]

        # Transpose the state back to its original form
        state = list(map(list, zip(*state)))

        return state